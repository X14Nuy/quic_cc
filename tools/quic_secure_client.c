#include "pico_cid_secure.h"
#include "traffic_profile.h"

#include <errno.h>
#include <limits.h>
#include <openssl/rand.h>
#include <picoquic.h>
#include <picoquic_packet_loop.h>
#include <picoquic_utils.h>
#include <picosocks.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#ifndef QSC_PROJECT_ROOT
#define QSC_PROJECT_ROOT "."
#endif

#define QC_DEFAULT_ALPN "h3"
#define QC_DEFAULT_SNI "localhost"
#define QC_DEFAULT_PROFILE_BPF "ip and udp"
#define QC_DEFAULT_DELAY_MS 10U
#define QC_DEFAULT_LISTEN_PORT 0U
#define QC_DEFAULT_INTERVAL_UNIT_SEC 60U
#define QC_DEFAULT_FRAG_RETRIES 3U
#define QC_MAX_FRAGMENTS 255U
#define QC_MAX_FRAG_DATA (PCS_CID_MAX_LEN - PCS_CID_MIN_LEN)
#define QC_CLOSE_DELAY_US 20000U
#define QC_AUTH_BUF_CAP 256U
#define QC_AUTH_COVER_MAX 96U

typedef struct client_opts_s {
    const char *server;
    uint16_t port;
    const char *psk_hex;
    const char *ca_cert;
    const char *alpn;
    const char *sni;
    const char *iface;
    const char *profile_bpf;
    uint8_t cid_len;

    uint16_t listen_port;
    const char *listen_cert;
    const char *listen_key;

    uint32_t interval_unit_sec;
    uint32_t entropy_len;
    uint32_t rounds;
    uint32_t frag_retries;

    const char *fixed_message;
} client_opts_t;

typedef struct uplink_conn_ctx_s {
    pcs_cid_fragment_t frag;
    uint8_t proof_payload[QC_AUTH_BUF_CAP];
    size_t proof_payload_len;
    uint8_t expected_ack_hash[PCS_HASH_LEN];

    uint8_t recv_buf[256];
    size_t recv_len;

    int proof_sent;
    int ack_ok;
    int close_requested;
    int disconnected;
    int fatal_error;
} uplink_conn_ctx_t;

typedef struct downlink_session_s {
    uint32_t session_id;
    uint8_t frag_total;
    uint8_t received_count;
    uint8_t received[QC_MAX_FRAGMENTS];
    uint8_t frag_len[QC_MAX_FRAGMENTS];
    uint8_t frag_data[QC_MAX_FRAGMENTS][QC_MAX_FRAG_DATA];
    struct downlink_session_s *next;
} downlink_session_t;

typedef struct listener_conn_ctx_s {
    struct client_runtime_s *runtime;
    uint8_t recv_buf[256];
    size_t recv_len;
    int close_pending;
    int released;
} listener_conn_ctx_t;

typedef struct client_runtime_s {
    client_opts_t opts;
    uint8_t psk[PCS_PSK_LEN];

    downlink_session_t *downlink_sessions;

    pthread_mutex_t downlink_lock;
    int listener_exit_code;
} client_runtime_t;

static volatile sig_atomic_t g_stop = 0;

static void on_signal(int signo)
{
    (void)signo;
    g_stop = 1;
}

static void usage(const char *prog)
{
    fprintf(stderr,
            "Usage: %s -s <server_ip_or_name> -p <port> [options]\n"
            "Options:\n"
            "  -k <psk_hex>       shared key, 64 hex chars\n"
            "  -c <cid_len>       CID length, 8..20 (default 20)\n"
            "  -C <ca_cert.pem>   CA/cert file for uplink handshake (default: <project>/certs/cert.pem)\n"
            "  -a <alpn>          ALPN (default: %s)\n"
            "  -n <sni>           SNI (default: %s)\n"
            "  -i <iface>         enable Module-A pacing sample from interface\n"
            "  -f <profile_bpf>   BPF for pacing profile (default: %s)\n"
            "  -L <listen_port>   local QUIC listen port for server push (default: random high port)\n"
            "  -E <cert.pem>      listener certificate (default: <project>/certs/cert.pem)\n"
            "  -G <key.pem>       listener private key (default: <project>/certs/key.pem)\n"
            "  -u <unit_sec>      seconds per interval unit (default: %u, i.e. minutes)\n"
            "  -e <bytes>         high-entropy message length (default: CID payload capacity)\n"
            "  -r <rounds>        send rounds, 0=forever (default 0)\n"
            "  -R <retries>       retries per CID fragment on failure (default: %u)\n"
            "  -m <message>       fixed message (debug mode; disables entropy generation)\n",
            prog,
            QC_DEFAULT_ALPN,
            QC_DEFAULT_SNI,
            QC_DEFAULT_PROFILE_BPF,
            QC_DEFAULT_INTERVAL_UNIT_SEC,
            QC_DEFAULT_FRAG_RETRIES);
}

static int is_printable_ascii(const uint8_t *buf, size_t len)
{
    size_t i;

    for (i = 0; i < len; ++i) {
        if ((buf[i] >= 32U && buf[i] <= 126U) || buf[i] == '\t' || buf[i] == '\n' || buf[i] == '\r') {
            continue;
        }
        return 0;
    }

    return 1;
}

static void sleep_ms(uint32_t ms)
{
    struct timespec req;

    req.tv_sec = (time_t)(ms / 1000U);
    req.tv_nsec = (long)((ms % 1000U) * 1000000UL);

    while (!g_stop && nanosleep(&req, &req) == -1 && errno == EINTR) {
    }
}

static void sleep_seconds_interruptible(uint64_t sec)
{
    while (!g_stop && sec > 0U) {
        sleep_ms(1000U);
        sec--;
    }
}

static uint32_t sample_delay_ms(int profile_enabled, traffic_profile_engine_t *profile)
{
    uint16_t sample_len = 0;
    uint32_t sample_delay = QC_DEFAULT_DELAY_MS;

    if (profile_enabled && profile != NULL &&
        tp_engine_sample(profile, &sample_len, &sample_delay) == 0) {
        if (sample_delay == 0U) {
            sample_delay = 1U;
        }
        if (sample_delay > 5000U) {
            sample_delay = 5000U;
        }
        return sample_delay;
    }

    return QC_DEFAULT_DELAY_MS;
}

static int entropy_fill(uint8_t *buf, size_t len)
{
    if (buf == NULL || len == 0U) {
        return -1;
    }

    if (RAND_bytes(buf, (int)len) == 1) {
        return 0;
    }

    return -2;
}

static int append_random_cover(uint8_t *buf, size_t cap, size_t *len_inout, size_t cover_max)
{
    uint16_t r = 0U;
    size_t cover_len;

    if (buf == NULL || len_inout == NULL) {
        return -1;
    }
    if (*len_inout > cap) {
        return -2;
    }
    if (cover_max == 0U || *len_inout == cap) {
        return 0;
    }
    if (RAND_bytes((uint8_t *)&r, sizeof(r)) != 1) {
        r = (uint16_t)time(NULL);
    }

    cover_len = (size_t)(r % (cover_max + 1U));
    if (cover_len > cap - *len_inout) {
        cover_len = cap - *len_inout;
    }
    if (cover_len == 0U) {
        return 0;
    }
    if (RAND_bytes(buf + *len_inout, (int)cover_len) != 1) {
        return -3;
    }
    *len_inout += cover_len;
    return 0;
}

static uint32_t random_u32(void)
{
    uint32_t v = 0U;

    if (RAND_bytes((uint8_t *)&v, sizeof(v)) != 1) {
        v = (uint32_t)time(NULL) ^ 0xA5C31F27U;
    }
    return v;
}

static uint8_t choose_cid_len_near_max(uint8_t cid_len_max)
{
    uint8_t low;
    uint32_t span;

    if (cid_len_max < PCS_CID_MIN_LEN) {
        return PCS_CID_MIN_LEN;
    }

    low = (cid_len_max > 4U) ? (uint8_t)(cid_len_max - 4U) : PCS_CID_MIN_LEN;
    if (low < PCS_CID_MIN_LEN) {
        low = PCS_CID_MIN_LEN;
    }
    if (low > cid_len_max) {
        low = cid_len_max;
    }

    span = (uint32_t)(cid_len_max - low + 1U);
    return (uint8_t)(low + (random_u32() % span));
}

static uint16_t pick_random_high_port(void)
{
    uint16_t v = 0;
    uint16_t p;

    if (RAND_bytes((uint8_t *)&v, sizeof(v)) != 1) {
        v = (uint16_t)time(NULL);
    }

    p = (uint16_t)(20000U + (v % 40000U));
    if (p == 0U) {
        p = 20000U;
    }
    return p;
}

static downlink_session_t *downlink_session_find(client_runtime_t *rt, uint32_t session_id)
{
    downlink_session_t *cur = rt->downlink_sessions;

    while (cur != NULL) {
        if (cur->session_id == session_id) {
            return cur;
        }
        cur = cur->next;
    }

    return NULL;
}

static downlink_session_t *downlink_session_get_or_create(client_runtime_t *rt,
                                                           uint32_t session_id,
                                                           uint8_t frag_total)
{
    downlink_session_t *s;

    s = downlink_session_find(rt, session_id);
    if (s != NULL) {
        if (s->frag_total != frag_total) {
            return NULL;
        }
        return s;
    }

    s = (downlink_session_t *)calloc(1, sizeof(*s));
    if (s == NULL) {
        return NULL;
    }

    s->session_id = session_id;
    s->frag_total = frag_total;
    s->next = rt->downlink_sessions;
    rt->downlink_sessions = s;
    return s;
}

static int downlink_session_store_fragment(client_runtime_t *rt, const pcs_cid_fragment_t *frag)
{
    downlink_session_t *s;
    uint8_t idx;

    if (rt == NULL || frag == NULL) {
        return -1;
    }
    if (frag->frag_total == 0U || frag->frag_total > QC_MAX_FRAGMENTS) {
        return -2;
    }
    if (frag->data_len > QC_MAX_FRAG_DATA) {
        return -3;
    }

    s = downlink_session_get_or_create(rt, frag->session_id, frag->frag_total);
    if (s == NULL) {
        return -4;
    }

    idx = frag->frag_idx;
    if (idx >= s->frag_total) {
        return -5;
    }

    if (s->received[idx]) {
        if (s->frag_len[idx] == frag->data_len &&
            memcmp(s->frag_data[idx], frag->data, frag->data_len) == 0) {
            return 1;
        }
        return -6;
    }

    s->received[idx] = 1U;
    s->frag_len[idx] = frag->data_len;
    if (frag->data_len > 0U) {
        memcpy(s->frag_data[idx], frag->data, frag->data_len);
    }
    s->received_count++;

    return 0;
}

static void downlink_session_remove(client_runtime_t *rt, downlink_session_t *target)
{
    downlink_session_t *prev = NULL;
    downlink_session_t *cur = rt->downlink_sessions;

    while (cur != NULL) {
        if (cur == target) {
            if (prev == NULL) {
                rt->downlink_sessions = cur->next;
            } else {
                prev->next = cur->next;
            }
            free(cur);
            return;
        }
        prev = cur;
        cur = cur->next;
    }
}

static void downlink_session_emit_if_complete(client_runtime_t *rt, uint32_t session_id)
{
    downlink_session_t *s = downlink_session_find(rt, session_id);
    size_t total_len = 0;
    size_t i;
    uint8_t *msg;

    if (s == NULL || s->received_count != s->frag_total) {
        return;
    }

    for (i = 0; i < s->frag_total; ++i) {
        total_len += s->frag_len[i];
    }

    msg = (uint8_t *)malloc(total_len + 1U);
    if (msg == NULL) {
        return;
    }

    total_len = 0;
    for (i = 0; i < s->frag_total; ++i) {
        if (s->frag_len[i] > 0U) {
            memcpy(msg + total_len, s->frag_data[i], s->frag_len[i]);
            total_len += s->frag_len[i];
        }
    }
    msg[total_len] = '\0';

    if (is_printable_ascii(msg, total_len)) {
        fprintf(stdout,
                "[client] downlink session=0x%08x complete, len=%zu, text=\"%s\"\n",
                session_id,
                total_len,
                msg);
    } else {
        char *hex = (char *)malloc(total_len * 2U + 1U);
        if (hex != NULL) {
            pcs_hex_encode(msg, total_len, hex, total_len * 2U + 1U);
            fprintf(stdout,
                    "[client] downlink session=0x%08x complete, len=%zu, hex=%s\n",
                    session_id,
                    total_len,
                    hex);
            free(hex);
        }
    }

    free(msg);
    downlink_session_remove(rt, s);
}

static void listener_release_conn_ctx(picoquic_cnx_t *cnx, listener_conn_ctx_t *conn)
{
    if (conn == NULL || conn->released) {
        return;
    }
    conn->released = 1;
    picoquic_set_callback(cnx, NULL, NULL);
    free(conn);
}

static int listener_handle_server_push(picoquic_cnx_t *cnx,
                                       uint64_t stream_id,
                                       listener_conn_ctx_t *conn)
{
    picoquic_connection_id_t icid;
    pcs_cid_fragment_t frag;
    pcs_auth_payload_t payload;
    uint8_t expected_hash[PCS_HASH_LEN];
    uint8_t ack_hash[PCS_HASH_LEN];
    uint8_t ack_payload[QC_AUTH_BUF_CAP];
    size_t ack_len = 0;
    int store_rc;

    icid = picoquic_get_initial_cnxid(cnx);
    if (icid.id_len < PCS_CID_MIN_LEN || icid.id_len > PCS_CID_MAX_LEN) {
        return -1;
    }

    if (pcs_decode_cid_fragment(icid.id, icid.id_len, &frag) != 0) {
        return -2;
    }
    if (pcs_parse_auth_payload(conn->recv_buf, conn->recv_len, &payload) != 0) {
        return -3;
    }
    if (payload.msg_type != PCS_MSG_SERVER_PUSH ||
        payload.session_id != frag.session_id ||
        payload.frag_idx != frag.frag_idx ||
        payload.frag_total != frag.frag_total ||
        payload.data_len != frag.data_len) {
        return -4;
    }

    if (pcs_compute_auth_hash(conn->runtime->psk,
                              PCS_MSG_SERVER_PUSH,
                              icid.id,
                              icid.id_len,
                              expected_hash) != 0) {
        return -5;
    }
    if (memcmp(expected_hash, payload.hash, PCS_HASH_LEN) != 0) {
        return -6;
    }

    pthread_mutex_lock(&conn->runtime->downlink_lock);
    store_rc = downlink_session_store_fragment(conn->runtime, &frag);
    if (store_rc >= 0) {
        downlink_session_emit_if_complete(conn->runtime, frag.session_id);
    }
    pthread_mutex_unlock(&conn->runtime->downlink_lock);

    if (store_rc < 0) {
        return -7;
    }

    if (pcs_compute_auth_hash(conn->runtime->psk,
                              PCS_MSG_CLIENT_PUSH_ACK,
                              icid.id,
                              icid.id_len,
                              ack_hash) != 0 ||
        pcs_build_auth_payload(PCS_MSG_CLIENT_PUSH_ACK,
                               &frag,
                               0U,
                               ack_hash,
                               ack_payload,
                               sizeof(ack_payload),
                               &ack_len) != 0) {
        return -8;
    }
    if (append_random_cover(ack_payload, sizeof(ack_payload), &ack_len, QC_AUTH_COVER_MAX) != 0) {
        return -10;
    }

    if (picoquic_add_to_stream(cnx, stream_id, ack_payload, ack_len, 1) != 0) {
        return -9;
    }

    conn->close_pending = 1;
    picoquic_set_app_wake_time(cnx, picoquic_current_time() + QC_CLOSE_DELAY_US);

    return 0;
}

static int listener_stream_callback(picoquic_cnx_t *cnx,
                                    uint64_t stream_id,
                                    uint8_t *bytes,
                                    size_t length,
                                    picoquic_call_back_event_t event,
                                    void *callback_ctx,
                                    void *stream_ctx)
{
    picoquic_quic_t *quic = picoquic_get_quic_ctx(cnx);
    client_runtime_t *runtime = (client_runtime_t *)picoquic_get_default_callback_context(quic);
    listener_conn_ctx_t *conn = (listener_conn_ctx_t *)callback_ctx;

    (void)stream_ctx;

    if (conn == NULL || callback_ctx == runtime) {
        conn = (listener_conn_ctx_t *)calloc(1, sizeof(*conn));
        if (conn == NULL) {
            return PICOQUIC_ERROR_MEMORY;
        }
        conn->runtime = runtime;
        picoquic_set_callback(cnx, listener_stream_callback, conn);
    }

    switch (event) {
    case picoquic_callback_stream_data:
    case picoquic_callback_stream_fin:
        if (stream_id != 0) {
            break;
        }

        if (length > 0U) {
            if (conn->recv_len + length > sizeof(conn->recv_buf)) {
                (void)picoquic_close(cnx, 0x301);
                return -1;
            }
            memcpy(conn->recv_buf + conn->recv_len, bytes, length);
            conn->recv_len += length;
        }

        if (event == picoquic_callback_stream_fin) {
            int rc = listener_handle_server_push(cnx, stream_id, conn);
            if (rc != 0) {
                (void)picoquic_close(cnx, 0x302);
                return -1;
            }
            {
                pcs_auth_payload_t parsed = {0};
                if (pcs_parse_auth_payload(conn->recv_buf, conn->recv_len, &parsed) == 0) {
                    fprintf(stdout,
                            "[client] verified downlink fragment session=0x%08x idx=%u/%u\n",
                            parsed.session_id,
                            parsed.frag_idx,
                            parsed.frag_total);
                }
            }
        }
        break;

    case picoquic_callback_app_wakeup:
        if (conn->close_pending) {
            conn->close_pending = 0;
            if (picoquic_close(cnx, 0) != 0) {
                return -1;
            }
        }
        break;

    case picoquic_callback_stateless_reset:
    case picoquic_callback_close:
    case picoquic_callback_application_close:
        listener_release_conn_ctx(cnx, conn);
        break;

    default:
        break;
    }

    return 0;
}

static int listener_packet_loop_cb(picoquic_quic_t *quic,
                                   picoquic_packet_loop_cb_enum cb_mode,
                                   void *callback_ctx,
                                   void *callback_arg)
{
    (void)quic;
    (void)callback_ctx;
    (void)callback_arg;

    switch (cb_mode) {
    case picoquic_packet_loop_ready:
        fprintf(stdout, "[client] downlink listener ready\n");
        break;

    case picoquic_packet_loop_after_receive:
    case picoquic_packet_loop_after_send:
    case picoquic_packet_loop_time_check:
        if (g_stop) {
            return PICOQUIC_NO_ERROR_TERMINATE_PACKET_LOOP;
        }
        break;

    default:
        break;
    }

    return 0;
}

static void *listener_thread_main(void *arg)
{
    client_runtime_t *rt = (client_runtime_t *)arg;
    picoquic_quic_t *quic = NULL;
    uint64_t now;
    int rc;

    if (rt == NULL) {
        return NULL;
    }

    now = picoquic_current_time();
    quic = picoquic_create(256,
                           rt->opts.listen_cert,
                           rt->opts.listen_key,
                           NULL,
                           rt->opts.alpn,
                           listener_stream_callback,
                           rt,
                           NULL,
                           NULL,
                           NULL,
                           now,
                           NULL,
                           NULL,
                           NULL,
                           0);
    if (quic == NULL) {
        rt->listener_exit_code = -1;
        fprintf(stderr,
                "[client] failed to create listener context (cert=%s key=%s)\n",
                rt->opts.listen_cert,
                rt->opts.listen_key);
        return NULL;
    }

    (void)picoquic_set_default_connection_id_length(quic, PCS_CID_MAX_LEN);
    picoquic_set_cookie_mode(quic, 2);

    fprintf(stdout,
            "[client] listening for server push on UDP/%u\n",
            (unsigned)rt->opts.listen_port);

    rc = picoquic_packet_loop(quic,
                              rt->opts.listen_port,
                              AF_INET,
                              0,
                              0,
                              1,
                              listener_packet_loop_cb,
                              rt);

    if (rc == PICOQUIC_NO_ERROR_TERMINATE_PACKET_LOOP) {
        rc = 0;
    }
    rt->listener_exit_code = rc;

    picoquic_free(quic);
    return NULL;
}

static int uplink_stream_callback(picoquic_cnx_t *cnx,
                                  uint64_t stream_id,
                                  uint8_t *bytes,
                                  size_t length,
                                  picoquic_call_back_event_t event,
                                  void *callback_ctx,
                                  void *stream_ctx)
{
    uplink_conn_ctx_t *ctx = (uplink_conn_ctx_t *)callback_ctx;

    (void)stream_ctx;

    if (ctx == NULL) {
        return PICOQUIC_ERROR_UNEXPECTED_ERROR;
    }

    switch (event) {
    case picoquic_callback_almost_ready:
    case picoquic_callback_ready:
        if (!ctx->proof_sent) {
            int rc = picoquic_add_to_stream(cnx,
                                            0,
                                            ctx->proof_payload,
                                            ctx->proof_payload_len,
                                            1);
            if (rc != 0) {
                ctx->fatal_error = -100;
                return rc;
            }
            ctx->proof_sent = 1;
        }
        break;

    case picoquic_callback_stream_data:
    case picoquic_callback_stream_fin:
        if (stream_id != 0) {
            break;
        }

        if (length > 0U) {
            if (ctx->recv_len + length > sizeof(ctx->recv_buf)) {
                ctx->fatal_error = -101;
                return -1;
            }
            memcpy(ctx->recv_buf + ctx->recv_len, bytes, length);
            ctx->recv_len += length;
        }

        if (event == picoquic_callback_stream_fin) {
            pcs_auth_payload_t ack = {0};

            if (pcs_parse_auth_payload(ctx->recv_buf, ctx->recv_len, &ack) != 0 ||
                ack.msg_type != PCS_MSG_SERVER_ACK ||
                ack.session_id != ctx->frag.session_id ||
                ack.frag_idx != ctx->frag.frag_idx ||
                ack.frag_total != ctx->frag.frag_total ||
                ack.data_len != ctx->frag.data_len ||
                memcmp(ack.hash, ctx->expected_ack_hash, PCS_HASH_LEN) != 0) {
                ctx->fatal_error = -102;
                return -1;
            }

            ctx->ack_ok = 1;
            if (!ctx->close_requested) {
                if (picoquic_close(cnx, 0) != 0) {
                    ctx->fatal_error = -103;
                    return -1;
                }
                ctx->close_requested = 1;
            }
        }
        break;

    case picoquic_callback_stateless_reset:
    case picoquic_callback_close:
    case picoquic_callback_application_close:
        ctx->disconnected = 1;
        break;

    default:
        break;
    }

    return 0;
}

static int uplink_packet_loop_cb(picoquic_quic_t *quic,
                                 picoquic_packet_loop_cb_enum cb_mode,
                                 void *callback_ctx,
                                 void *callback_arg)
{
    uplink_conn_ctx_t *ctx = (uplink_conn_ctx_t *)callback_ctx;

    (void)quic;
    (void)callback_arg;

    if (ctx == NULL) {
        return PICOQUIC_ERROR_UNEXPECTED_ERROR;
    }

    switch (cb_mode) {
    case picoquic_packet_loop_ready:
    case picoquic_packet_loop_port_update:
        return 0;

    case picoquic_packet_loop_after_receive:
    case picoquic_packet_loop_after_send:
        if (ctx->fatal_error != 0) {
            return ctx->fatal_error;
        }
        if (ctx->disconnected) {
            return PICOQUIC_NO_ERROR_TERMINATE_PACKET_LOOP;
        }
        return 0;

    default:
        return 0;
    }
}

static int run_one_uplink_fragment(const client_runtime_t *rt,
                                   const struct sockaddr_storage *server_addr,
                                   const uint8_t *cid,
                                   uint8_t cid_len,
                                   const pcs_cid_fragment_t *frag)
{
    picoquic_quic_t *quic = NULL;
    picoquic_cnx_t *cnx = NULL;
    picoquic_connection_id_t initial_cid = {0};
    uplink_conn_ctx_t conn_ctx;
    uint8_t proof_hash[PCS_HASH_LEN];
    uint64_t now = picoquic_current_time();
    int ret;

    if (rt == NULL || server_addr == NULL || cid == NULL || frag == NULL) {
        return -1;
    }

    memset(&conn_ctx, 0, sizeof(conn_ctx));
    conn_ctx.frag = *frag;

    if (pcs_compute_auth_hash(rt->psk,
                              PCS_MSG_CLIENT_PROOF,
                              cid,
                              cid_len,
                              proof_hash) != 0 ||
        pcs_compute_auth_hash(rt->psk,
                              PCS_MSG_SERVER_ACK,
                              cid,
                              cid_len,
                              conn_ctx.expected_ack_hash) != 0 ||
        pcs_build_auth_payload(PCS_MSG_CLIENT_PROOF,
                               frag,
                               rt->opts.listen_port,
                               proof_hash,
                               conn_ctx.proof_payload,
                               sizeof(conn_ctx.proof_payload),
                               &conn_ctx.proof_payload_len) != 0) {
        return -2;
    }
    if (append_random_cover(conn_ctx.proof_payload,
                            sizeof(conn_ctx.proof_payload),
                            &conn_ctx.proof_payload_len,
                            QC_AUTH_COVER_MAX) != 0) {
        return -8;
    }

    quic = picoquic_create(1,
                           NULL,
                           NULL,
                           rt->opts.ca_cert,
                           rt->opts.alpn,
                           NULL,
                           NULL,
                           NULL,
                           NULL,
                           NULL,
                           now,
                           NULL,
                           NULL,
                           NULL,
                           0);
    if (quic == NULL) {
        return -3;
    }

    picoquic_set_null_verifier(quic);
    (void)picoquic_set_default_connection_id_length(quic, cid_len);

    initial_cid.id_len = cid_len;
    memcpy(initial_cid.id, cid, cid_len);

    cnx = picoquic_create_cnx(quic,
                              initial_cid,
                              picoquic_null_connection_id,
                              (const struct sockaddr *)server_addr,
                              now,
                              0,
                              rt->opts.sni,
                              rt->opts.alpn,
                              1);
    if (cnx == NULL) {
        picoquic_free(quic);
        return -4;
    }

    picoquic_set_callback(cnx, uplink_stream_callback, &conn_ctx);

    ret = picoquic_start_client_cnx(cnx);
    if (ret != 0) {
        picoquic_free(quic);
        return -5;
    }

    ret = picoquic_packet_loop(quic,
                               0,
                               ((const struct sockaddr *)server_addr)->sa_family,
                               0,
                               0,
                               1,
                               uplink_packet_loop_cb,
                               &conn_ctx);

    picoquic_free(quic);

    if (ret == PICOQUIC_NO_ERROR_TERMINATE_PACKET_LOOP) {
        ret = 0;
    }
    if (ret != 0) {
        return -6;
    }
    if (!conn_ctx.ack_ok) {
        return -7;
    }

    return 0;
}

static int send_uplink_message(client_runtime_t *rt,
                               const struct sockaddr_storage *server_addr,
                               const uint8_t *msg,
                               size_t msg_len,
                               int profile_enabled,
                               traffic_profile_engine_t *profile)
{
    uint32_t session_id = 0;
    typedef struct frag_plan_s {
        uint8_t chunk;
        uint8_t cid_len;
    } frag_plan_t;
    frag_plan_t plan[255];
    size_t frag_total = 0;
    size_t offset = 0;
    size_t remaining;
    size_t i;

    if (rt == NULL || server_addr == NULL || msg == NULL || msg_len == 0U) {
        return -1;
    }

    if (pcs_cid_fragment_capacity(rt->opts.cid_len) == 0U) {
        return -2;
    }

    remaining = msg_len;
    while (remaining > 0U && frag_total < 255U) {
        uint8_t cid_len = choose_cid_len_near_max(rt->opts.cid_len);
        size_t cap = pcs_cid_fragment_capacity(cid_len);
        size_t chunk = (remaining < cap) ? remaining : cap;

        if (cap == 0U) {
            return -3;
        }
        if (chunk == 0U || chunk > 255U) {
            return -4;
        }

        plan[frag_total].chunk = (uint8_t)chunk;
        plan[frag_total].cid_len = cid_len;
        remaining -= chunk;
        frag_total++;
    }

    if (remaining > 0U || frag_total == 0U) {
        return -5;
    }

    if (RAND_bytes((uint8_t *)&session_id, sizeof(session_id)) != 1) {
        session_id = (uint32_t)time(NULL);
    }

    fprintf(stdout,
            "[client] uplink session=0x%08x len=%zu fragments=%zu\n",
            session_id,
            msg_len,
            frag_total);

    for (i = 0; i < frag_total && !g_stop; ++i) {
        pcs_cid_fragment_t frag;
        uint8_t cid[PCS_CID_MAX_LEN];
        size_t chunk = plan[i].chunk;
        uint8_t cid_len = plan[i].cid_len;
        char cid_hex[PCS_CID_MAX_LEN * 2U + 1U];
        int rc;
        uint32_t attempt;

        memset(&frag, 0, sizeof(frag));
        frag.session_id = session_id;
        frag.frag_idx = (uint8_t)i;
        frag.frag_total = (uint8_t)frag_total;
        frag.data_len = (uint8_t)chunk;
        memcpy(frag.data, msg + offset, chunk);

        if (pcs_encode_cid_fragment(cid, cid_len, &frag) != 0) {
            return -6;
        }

        pcs_hex_encode(cid, cid_len, cid_hex, sizeof(cid_hex));
        fprintf(stdout,
                "[client] sending uplink fragment %zu/%zu cid_len=%u cid=%s\n",
                i + 1U,
                frag_total,
                (unsigned)cid_len,
                cid_hex);

        rc = -1;
        for (attempt = 0U; attempt <= rt->opts.frag_retries && !g_stop; ++attempt) {
            uint32_t retry_delay_ms;

            rc = run_one_uplink_fragment(rt, server_addr, cid, cid_len, &frag);
            if (rc == 0) {
                break;
            }

            if (attempt >= rt->opts.frag_retries) {
                break;
            }

            retry_delay_ms = sample_delay_ms(profile_enabled, profile);
            if (retry_delay_ms < 80U) {
                retry_delay_ms = 80U;
            }
            retry_delay_ms += (random_u32() % (retry_delay_ms + 1U));

            fprintf(stderr,
                    "[client] fragment %zu/%zu attempt %u failed (rc=%d), retry in %ums\n",
                    i + 1U,
                    frag_total,
                    attempt + 1U,
                    rc,
                    retry_delay_ms);
            sleep_ms(retry_delay_ms);
        }

        if (rc != 0) {
            fprintf(stderr,
                    "[client] uplink fragment %zu/%zu failed after %u retries (rc=%d)\n",
                    i + 1U,
                    frag_total,
                    rt->opts.frag_retries,
                    rc);
            return -7;
        }

        offset += chunk;

        if ((i + 1U) < frag_total) {
            uint32_t delay_ms = sample_delay_ms(profile_enabled, profile);
            delay_ms = (delay_ms / 2U) + (random_u32() % (delay_ms + 1U));
            sleep_ms(delay_ms);
        }
    }

    return 0;
}

static uint64_t compute_next_interval_sec(uint32_t unit_sec)
{
    uint64_t utc_now = (uint64_t)time(NULL);
    uint64_t minutes = utc_now % 60ULL;
    uint64_t base;
    uint16_t rnd = 0U;
    int32_t jitter_sign;
    uint64_t jitter_abs;

    if (minutes == 0ULL) {
        minutes = 1ULL;
    }

    base = minutes * (uint64_t)unit_sec;

    /*
     * Keep the requested UTC%60 periodicity as baseline, but add bounded
     * jitter to avoid a rigid timing fingerprint.
     */
    if (RAND_bytes((uint8_t *)&rnd, sizeof(rnd)) != 1) {
        rnd = (uint16_t)time(NULL);
    }
    jitter_sign = (rnd & 0x1U) ? 1 : -1;
    jitter_abs = (uint64_t)((rnd >> 1) % ((base / 5ULL) + 1ULL)); /* <=20% */

    if (jitter_sign < 0) {
        if (jitter_abs >= base) {
            return 1ULL;
        }
        return base - jitter_abs;
    }

    return base + jitter_abs;
}

static int build_entropy_message(client_runtime_t *rt,
                                 uint8_t **msg_out,
                                 size_t *msg_len_out,
                                 uint32_t round_idx)
{
    size_t frag_cap;
    size_t msg_len;
    uint8_t *buf;

    if (rt == NULL || msg_out == NULL || msg_len_out == NULL) {
        return -1;
    }

    frag_cap = pcs_cid_fragment_capacity(rt->opts.cid_len);
    if (frag_cap == 0U) {
        return -2;
    }

    msg_len = rt->opts.entropy_len;
    if (msg_len == 0U) {
        msg_len = frag_cap;
    }

    if (msg_len > frag_cap * 255U) {
        msg_len = frag_cap * 255U;
    }

    buf = (uint8_t *)malloc(msg_len);
    if (buf == NULL) {
        return -3;
    }

    if (entropy_fill(buf, msg_len) != 0) {
        free(buf);
        return -4;
    }

    if (msg_len >= 8U) {
        uint32_t t = (uint32_t)time(NULL);
        buf[0] ^= (uint8_t)(t >> 24);
        buf[1] ^= (uint8_t)(t >> 16);
        buf[2] ^= (uint8_t)(t >> 8);
        buf[3] ^= (uint8_t)t;
        buf[4] ^= (uint8_t)(round_idx >> 24);
        buf[5] ^= (uint8_t)(round_idx >> 16);
        buf[6] ^= (uint8_t)(round_idx >> 8);
        buf[7] ^= (uint8_t)round_idx;
    }

    *msg_out = buf;
    *msg_len_out = msg_len;
    return 0;
}

int main(int argc, char **argv)
{
    client_runtime_t runtime;
    struct sockaddr_storage server_addr;
    int is_name = 0;
    int opt;
    int rc = 1;
    char default_ca[PATH_MAX];
    char default_cert[PATH_MAX];
    char default_key[PATH_MAX];
    traffic_profile_engine_t profile;
    int profile_initialized = 0;
    int profile_enabled = 0;
    pthread_t listener_tid;
    int listener_started = 0;
    uint32_t round_idx = 0;
    int loop_failed = 0;

    memset(&runtime, 0, sizeof(runtime));
    memset(&server_addr, 0, sizeof(server_addr));
    memset(&profile, 0, sizeof(profile));

    snprintf(default_ca, sizeof(default_ca), "%s/certs/cert.pem", QSC_PROJECT_ROOT);
    snprintf(default_cert, sizeof(default_cert), "%s/certs/cert.pem", QSC_PROJECT_ROOT);
    snprintf(default_key, sizeof(default_key), "%s/certs/key.pem", QSC_PROJECT_ROOT);

    runtime.opts.cid_len = PCS_CID_MAX_LEN;
    runtime.opts.alpn = QC_DEFAULT_ALPN;
    runtime.opts.sni = QC_DEFAULT_SNI;
    runtime.opts.profile_bpf = QC_DEFAULT_PROFILE_BPF;
    runtime.opts.ca_cert = default_ca;
    runtime.opts.listen_port = QC_DEFAULT_LISTEN_PORT;
    runtime.opts.listen_cert = default_cert;
    runtime.opts.listen_key = default_key;
    runtime.opts.interval_unit_sec = QC_DEFAULT_INTERVAL_UNIT_SEC;
    runtime.opts.frag_retries = QC_DEFAULT_FRAG_RETRIES;

    while ((opt = getopt(argc, argv, "s:p:k:c:C:a:n:i:f:L:E:G:u:e:r:R:m:h")) != -1) {
        switch (opt) {
        case 's':
            runtime.opts.server = optarg;
            break;
        case 'p':
            runtime.opts.port = (uint16_t)strtoul(optarg, NULL, 10);
            break;
        case 'k':
            runtime.opts.psk_hex = optarg;
            break;
        case 'c':
            runtime.opts.cid_len = (uint8_t)strtoul(optarg, NULL, 10);
            break;
        case 'C':
            runtime.opts.ca_cert = optarg;
            break;
        case 'a':
            runtime.opts.alpn = optarg;
            break;
        case 'n':
            runtime.opts.sni = optarg;
            break;
        case 'i':
            runtime.opts.iface = optarg;
            break;
        case 'f':
            runtime.opts.profile_bpf = optarg;
            break;
        case 'L':
            runtime.opts.listen_port = (uint16_t)strtoul(optarg, NULL, 10);
            break;
        case 'E':
            runtime.opts.listen_cert = optarg;
            break;
        case 'G':
            runtime.opts.listen_key = optarg;
            break;
        case 'u':
            runtime.opts.interval_unit_sec = (uint32_t)strtoul(optarg, NULL, 10);
            break;
        case 'e':
            runtime.opts.entropy_len = (uint32_t)strtoul(optarg, NULL, 10);
            break;
        case 'r':
            runtime.opts.rounds = (uint32_t)strtoul(optarg, NULL, 10);
            break;
        case 'R':
            runtime.opts.frag_retries = (uint32_t)strtoul(optarg, NULL, 10);
            break;
        case 'm':
            runtime.opts.fixed_message = optarg;
            break;
        default:
            usage(argv[0]);
            return 1;
        }
    }

    if (runtime.opts.server == NULL || runtime.opts.port == 0U) {
        usage(argv[0]);
        return 1;
    }
    if (runtime.opts.cid_len < PCS_CID_MIN_LEN || runtime.opts.cid_len > PCS_CID_MAX_LEN) {
        fprintf(stderr, "invalid CID length: %u (must be 8..20)\n", runtime.opts.cid_len);
        return 1;
    }
    if (runtime.opts.interval_unit_sec == 0U) {
        fprintf(stderr, "invalid interval unit sec\n");
        return 1;
    }
    if (runtime.opts.frag_retries > 20U) {
        fprintf(stderr, "invalid fragment retries: %u (must be <=20)\n", runtime.opts.frag_retries);
        return 1;
    }

    if (runtime.opts.psk_hex != NULL) {
        if (runtime.opts.psk_hex[0] == '\0') {
            fprintf(stderr, "empty -k value\n");
            return 1;
        }
        if (pcs_parse_psk_hex(runtime.opts.psk_hex, runtime.psk) != 0) {
            fprintf(stderr, "invalid PSK format, expected 64 hex chars\n");
            return 1;
        }
    } else {
        pcs_default_psk(runtime.psk);
    }

    if (signal(SIGINT, on_signal) == SIG_ERR || signal(SIGTERM, on_signal) == SIG_ERR) {
        perror("signal");
        return 1;
    }

    if (pthread_mutex_init(&runtime.downlink_lock, NULL) != 0) {
        fprintf(stderr, "failed to init downlink mutex\n");
        return 1;
    }

    if (picoquic_get_server_address(runtime.opts.server,
                                    runtime.opts.port,
                                    &server_addr,
                                    &is_name) != 0) {
        fprintf(stderr,
                "failed to resolve server %s:%u\n",
                runtime.opts.server,
                runtime.opts.port);
        goto cleanup;
    }

    if (strcmp(runtime.opts.sni, QC_DEFAULT_SNI) == 0 && is_name) {
        runtime.opts.sni = runtime.opts.server;
    }

    if (runtime.opts.listen_port == 0U) {
        runtime.opts.listen_port = pick_random_high_port();
    }

    if (runtime.opts.iface != NULL) {
        if (tp_engine_init(&profile, 5000U, 256U) == 0) {
            profile_initialized = 1;
            if (tp_engine_start_capture(&profile,
                                        runtime.opts.iface,
                                        runtime.opts.profile_bpf,
                                        2048,
                                        1,
                                        100) == 0) {
                profile_enabled = 1;
                fprintf(stdout,
                        "[client] pacing profiler enabled on %s (%s)\n",
                        runtime.opts.iface,
                        runtime.opts.profile_bpf);
            } else {
                fprintf(stderr,
                        "[client] warning: failed to start profiler on %s, fallback delay=%ums\n",
                        runtime.opts.iface,
                        QC_DEFAULT_DELAY_MS);
            }
        } else {
            fprintf(stderr,
                    "[client] warning: failed to init profiler, fallback delay=%ums\n",
                    QC_DEFAULT_DELAY_MS);
        }
    }

    if (pthread_create(&listener_tid, NULL, listener_thread_main, &runtime) == 0) {
        listener_started = 1;
    } else {
        fprintf(stderr, "[client] failed to start listener thread\n");
        goto cleanup;
    }

    sleep_ms(200U);

    fprintf(stdout,
            "[client] uplink scheduler started: interval=(UTC%%60)*%us rounds=%u\n",
            runtime.opts.interval_unit_sec,
            runtime.opts.rounds);

    while (!g_stop) {
        uint8_t *msg = NULL;
        size_t msg_len = 0;
        char msg_hex[PCS_CID_MAX_LEN * 2U * 4U + 1U];

        round_idx++;

        if (runtime.opts.fixed_message != NULL) {
            msg_len = strlen(runtime.opts.fixed_message);
            msg = (uint8_t *)malloc(msg_len);
            if (msg == NULL) {
                fprintf(stderr, "[client] out of memory\n");
                break;
            }
            memcpy(msg, runtime.opts.fixed_message, msg_len);
        } else {
            if (build_entropy_message(&runtime, &msg, &msg_len, round_idx) != 0) {
                fprintf(stderr, "[client] failed to build entropy message\n");
                break;
            }
            pcs_hex_encode(msg,
                           (msg_len > 32U) ? 32U : msg_len,
                           msg_hex,
                           sizeof(msg_hex));
            fprintf(stdout,
                    "[client] round=%u entropy_len=%zu sample_hex=%s\n",
                    round_idx,
                    msg_len,
                    msg_hex);
        }

        if (msg_len == 0U) {
            free(msg);
            fprintf(stderr, "[client] empty message not allowed\n");
            break;
        }

        if (send_uplink_message(&runtime,
                                &server_addr,
                                msg,
                                msg_len,
                                profile_enabled,
                                &profile) != 0) {
            free(msg);
            loop_failed = 1;
            break;
        }

        free(msg);

        if (runtime.opts.rounds > 0U && round_idx >= runtime.opts.rounds) {
            break;
        }

        if (runtime.opts.fixed_message != NULL) {
            break;
        }

        {
            uint64_t wait_sec = compute_next_interval_sec(runtime.opts.interval_unit_sec);
            fprintf(stdout,
                    "[client] next uplink in %llu sec (UTC%%60 rule)\n",
                    (unsigned long long)wait_sec);
            sleep_seconds_interruptible(wait_sec);
        }
    }

    rc = loop_failed ? 1 : 0;

cleanup:
    g_stop = 1;

    if (listener_started) {
        (void)pthread_join(listener_tid, NULL);
    }

    if (profile_initialized) {
        tp_engine_destroy(&profile);
    }

    pthread_mutex_lock(&runtime.downlink_lock);
    while (runtime.downlink_sessions != NULL) {
        downlink_session_t *next = runtime.downlink_sessions->next;
        free(runtime.downlink_sessions);
        runtime.downlink_sessions = next;
    }
    pthread_mutex_unlock(&runtime.downlink_lock);
    pthread_mutex_destroy(&runtime.downlink_lock);

    if (runtime.listener_exit_code != 0 && runtime.listener_exit_code != PICOQUIC_NO_ERROR_TERMINATE_PACKET_LOOP) {
        fprintf(stderr, "[client] listener exited with rc=%d\n", runtime.listener_exit_code);
        if (rc == 0) {
            rc = 1;
        }
    }

    return rc;
}
