#include "pico_cid_secure.h"

#include <arpa/inet.h>
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
#include <sys/select.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#ifndef QSC_PROJECT_ROOT
#define QSC_PROJECT_ROOT "."
#endif

#define QS_DEFAULT_ALPN "qsc_cid_auth_v1"
#define QS_DEFAULT_SNI "localhost"
#define QS_MAX_FRAGMENTS 255U
#define QS_MAX_FRAG_DATA (PCS_CID_MAX_LEN - PCS_CID_MIN_LEN)
#define QS_CLIENT_IDLE_EXPIRE_SEC 3600U
#define QS_DEFAULT_CLIENT_PUSH_PORT 5544U
#define QS_PUSH_CLOSE_DELAY_US 20000U
#define QS_SEND_INTER_FRAG_DELAY_MS 10U
#define QS_CMD_BUF_SIZE 2048U

typedef struct server_session_s {
    uint32_t session_id;
    uint8_t frag_total;
    uint8_t received_count;
    uint8_t received[QS_MAX_FRAGMENTS];
    uint8_t frag_len[QS_MAX_FRAGMENTS];
    uint8_t frag_data[QS_MAX_FRAGMENTS][QS_MAX_FRAG_DATA];
    struct server_session_s *next;
} server_session_t;

typedef struct server_client_entry_s {
    char ip[INET6_ADDRSTRLEN];
    uint16_t peer_port;
    time_t first_seen_utc;
    time_t last_seen_utc;
    double prev_gap_sec;
    uint64_t msg_count;
    struct server_client_entry_s *next;
} server_client_entry_t;

typedef struct server_runtime_s {
    uint8_t psk[PCS_PSK_LEN];
    uint8_t cid_len;
    uint16_t client_push_port;
    const char *alpn;
    const char *sni;
    const char *ca_cert;

    server_session_t *sessions;

    pthread_mutex_t clients_lock;
    server_client_entry_t *clients;
} server_runtime_t;

typedef struct server_conn_ctx_s {
    server_runtime_t *runtime;
    uint8_t recv_buf[256];
    size_t recv_len;
    int close_pending;
    int released;
} server_conn_ctx_t;

typedef struct push_conn_ctx_s {
    pcs_cid_fragment_t frag;
    uint8_t proof_payload[PCS_AUTH_PAYLOAD_LEN];
    size_t proof_payload_len;
    uint8_t expected_ack_hash[PCS_HASH_LEN];

    uint8_t recv_buf[256];
    size_t recv_len;

    int proof_sent;
    int ack_ok;
    int close_requested;
    int disconnected;
    int fatal_error;
} push_conn_ctx_t;

typedef struct server_opts_s {
    uint16_t port;
    const char *cert_file;
    const char *key_file;
    const char *alpn;
    const char *psk_hex;

    uint8_t cid_len;
    uint16_t client_push_port;
    const char *push_sni;
    const char *ca_cert;
} server_opts_t;

typedef struct push_target_s {
    char ip[INET6_ADDRSTRLEN];
} push_target_t;

static volatile sig_atomic_t g_stop = 0;

static void on_signal(int signo)
{
    (void)signo;
    g_stop = 1;
}

static void usage(const char *prog)
{
    fprintf(stderr,
            "Usage: %s -p <port> [options]\n"
            "Options:\n"
            "  -C <cert.pem>      server certificate (default: <project>/certs/cert.pem)\n"
            "  -K <key.pem>       server private key (default: <project>/certs/key.pem)\n"
            "  -k <psk_hex>       shared key, 64 hex chars\n"
            "  -a <alpn>          ALPN (default: %s)\n"
            "  -c <cid_len>       CID length for server->client push, 8..20 (default: 20)\n"
            "  -P <port>          client listen port for server push (default: %u)\n"
            "  -n <sni>           SNI for server push connections (default: %s)\n"
            "  -A <ca.pem>        CA file for server push (default: <project>/certs/cert.pem)\n"
            "\n"
            "Runtime commands (stdin):\n"
            "  list\n"
            "  send all <message>\n"
            "  send <ip> <message>\n"
            "  help\n",
            prog,
            QS_DEFAULT_ALPN,
            QS_DEFAULT_CLIENT_PUSH_PORT,
            QS_DEFAULT_SNI);
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

    while (nanosleep(&req, &req) == -1 && !g_stop) {
    }
}

static void format_utc(time_t ts, char *out, size_t out_cap)
{
    struct tm tmv;

    if (out == NULL || out_cap == 0U) {
        return;
    }
    if (gmtime_r(&ts, &tmv) == NULL) {
        snprintf(out, out_cap, "<invalid>");
        return;
    }
    if (strftime(out, out_cap, "%Y-%m-%dT%H:%M:%SZ", &tmv) == 0U) {
        snprintf(out, out_cap, "<invalid>");
    }
}

static int extract_peer_ip_port(picoquic_cnx_t *cnx,
                                char *ip,
                                size_t ip_cap,
                                uint16_t *port)
{
    struct sockaddr *peer_addr = NULL;

    if (cnx == NULL || ip == NULL || ip_cap == 0U || port == NULL) {
        return -1;
    }

    picoquic_get_peer_addr(cnx, &peer_addr);
    if (peer_addr == NULL) {
        return -2;
    }

    if (peer_addr->sa_family == AF_INET) {
        const struct sockaddr_in *sa = (const struct sockaddr_in *)peer_addr;
        if (inet_ntop(AF_INET, &sa->sin_addr, ip, ip_cap) == NULL) {
            return -3;
        }
        *port = ntohs(sa->sin_port);
        return 0;
    }

    if (peer_addr->sa_family == AF_INET6) {
        const struct sockaddr_in6 *sa6 = (const struct sockaddr_in6 *)peer_addr;
        if (inet_ntop(AF_INET6, &sa6->sin6_addr, ip, ip_cap) == NULL) {
            return -4;
        }
        *port = ntohs(sa6->sin6_port);
        return 0;
    }

    return -5;
}

static void client_list_prune_locked(server_runtime_t *rt, time_t now_utc)
{
    server_client_entry_t *prev = NULL;
    server_client_entry_t *cur = NULL;

    if (rt == NULL) {
        return;
    }

    cur = rt->clients;
    while (cur != NULL) {
        double age = difftime(now_utc, cur->last_seen_utc);
        if (age > (double)QS_CLIENT_IDLE_EXPIRE_SEC) {
            server_client_entry_t *victim = cur;
            if (prev == NULL) {
                rt->clients = cur->next;
            } else {
                prev->next = cur->next;
            }
            cur = cur->next;
            free(victim);
            continue;
        }
        prev = cur;
        cur = cur->next;
    }
}

static server_client_entry_t *client_list_find_locked(server_runtime_t *rt, const char *ip)
{
    server_client_entry_t *cur;

    if (rt == NULL || ip == NULL) {
        return NULL;
    }

    cur = rt->clients;
    while (cur != NULL) {
        if (strcmp(cur->ip, ip) == 0) {
            return cur;
        }
        cur = cur->next;
    }

    return NULL;
}

static void client_list_update_from_conn(server_runtime_t *rt, picoquic_cnx_t *cnx)
{
    char ip[INET6_ADDRSTRLEN];
    uint16_t port = 0;
    time_t now_utc;
    server_client_entry_t *entry;

    if (rt == NULL || cnx == NULL) {
        return;
    }

    if (extract_peer_ip_port(cnx, ip, sizeof(ip), &port) != 0) {
        return;
    }

    now_utc = time(NULL);

    pthread_mutex_lock(&rt->clients_lock);
    client_list_prune_locked(rt, now_utc);

    entry = client_list_find_locked(rt, ip);
    if (entry == NULL) {
        entry = (server_client_entry_t *)calloc(1, sizeof(*entry));
        if (entry != NULL) {
            snprintf(entry->ip, sizeof(entry->ip), "%s", ip);
            entry->peer_port = port;
            entry->first_seen_utc = now_utc;
            entry->last_seen_utc = now_utc;
            entry->prev_gap_sec = 0.0;
            entry->msg_count = 1U;
            entry->next = rt->clients;
            rt->clients = entry;
        }
    } else {
        entry->prev_gap_sec = difftime(now_utc, entry->last_seen_utc);
        entry->last_seen_utc = now_utc;
        entry->peer_port = port;
        entry->msg_count++;
    }

    pthread_mutex_unlock(&rt->clients_lock);
}

static size_t client_list_snapshot(server_runtime_t *rt,
                                   const char *target,
                                   push_target_t **targets_out)
{
    size_t count = 0;
    size_t idx = 0;
    time_t now_utc;
    int send_all;
    server_client_entry_t *cur;
    push_target_t *targets;

    if (rt == NULL || target == NULL || targets_out == NULL) {
        return 0U;
    }

    send_all = (strcmp(target, "all") == 0);
    *targets_out = NULL;

    now_utc = time(NULL);

    pthread_mutex_lock(&rt->clients_lock);
    client_list_prune_locked(rt, now_utc);

    cur = rt->clients;
    while (cur != NULL) {
        if (send_all || strcmp(cur->ip, target) == 0) {
            count++;
        }
        cur = cur->next;
    }

    if (count == 0U) {
        pthread_mutex_unlock(&rt->clients_lock);
        return 0U;
    }

    targets = (push_target_t *)calloc(count, sizeof(*targets));
    if (targets == NULL) {
        pthread_mutex_unlock(&rt->clients_lock);
        return 0U;
    }

    cur = rt->clients;
    while (cur != NULL && idx < count) {
        if (send_all || strcmp(cur->ip, target) == 0) {
            snprintf(targets[idx].ip, sizeof(targets[idx].ip), "%s", cur->ip);
            idx++;
        }
        cur = cur->next;
    }

    pthread_mutex_unlock(&rt->clients_lock);

    *targets_out = targets;
    return idx;
}

static void client_list_print(server_runtime_t *rt)
{
    server_client_entry_t *cur;
    time_t now_utc;
    size_t n = 0;

    if (rt == NULL) {
        return;
    }

    now_utc = time(NULL);

    pthread_mutex_lock(&rt->clients_lock);
    client_list_prune_locked(rt, now_utc);

    fprintf(stdout, "[server] client list:\n");
    cur = rt->clients;
    while (cur != NULL) {
        char first_seen[32];
        double age_sec = difftime(now_utc, cur->last_seen_utc);
        format_utc(cur->first_seen_utc, first_seen, sizeof(first_seen));

        fprintf(stdout,
                "  ip=%s peer_port=%u first=%s age_since_last=%.0fs last_gap=%.0fs msg_count=%llu\n",
                cur->ip,
                (unsigned)cur->peer_port,
                first_seen,
                age_sec,
                cur->prev_gap_sec,
                (unsigned long long)cur->msg_count);
        n++;
        cur = cur->next;
    }

    if (n == 0U) {
        fprintf(stdout, "  <empty>\n");
    }

    pthread_mutex_unlock(&rt->clients_lock);
}

static server_session_t *session_find(server_runtime_t *rt, uint32_t session_id)
{
    server_session_t *cur = rt->sessions;

    while (cur != NULL) {
        if (cur->session_id == session_id) {
            return cur;
        }
        cur = cur->next;
    }

    return NULL;
}

static server_session_t *session_get_or_create(server_runtime_t *rt,
                                               uint32_t session_id,
                                               uint8_t frag_total)
{
    server_session_t *s;

    s = session_find(rt, session_id);
    if (s != NULL) {
        if (s->frag_total != frag_total) {
            return NULL;
        }
        return s;
    }

    s = (server_session_t *)calloc(1, sizeof(*s));
    if (s == NULL) {
        return NULL;
    }

    s->session_id = session_id;
    s->frag_total = frag_total;
    s->next = rt->sessions;
    rt->sessions = s;
    return s;
}

static int session_store_fragment(server_runtime_t *rt, const pcs_cid_fragment_t *frag)
{
    server_session_t *s;
    uint8_t idx;

    if (rt == NULL || frag == NULL) {
        return -1;
    }
    if (frag->frag_total == 0U || frag->frag_total > QS_MAX_FRAGMENTS) {
        return -2;
    }
    if (frag->data_len > QS_MAX_FRAG_DATA) {
        return -3;
    }

    s = session_get_or_create(rt, frag->session_id, frag->frag_total);
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

static void session_remove(server_runtime_t *rt, server_session_t *target)
{
    server_session_t *prev = NULL;
    server_session_t *cur = rt->sessions;

    while (cur != NULL) {
        if (cur == target) {
            if (prev == NULL) {
                rt->sessions = cur->next;
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

static void session_emit_if_complete(server_runtime_t *rt, uint32_t session_id)
{
    server_session_t *s = session_find(rt, session_id);
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
                "[server] uplink session=0x%08x complete, len=%zu, text=\"%s\"\n",
                session_id,
                total_len,
                msg);
    } else {
        char *hex = (char *)malloc(total_len * 2U + 1U);
        if (hex != NULL) {
            pcs_hex_encode(msg, total_len, hex, total_len * 2U + 1U);
            fprintf(stdout,
                    "[server] uplink session=0x%08x complete, len=%zu, hex=%s\n",
                    session_id,
                    total_len,
                    hex);
            free(hex);
        }
    }

    free(msg);
    session_remove(rt, s);
}

static void release_conn_ctx(picoquic_cnx_t *cnx, server_conn_ctx_t *conn)
{
    if (conn == NULL || conn->released) {
        return;
    }
    conn->released = 1;
    picoquic_set_callback(cnx, NULL, NULL);
    free(conn);
}

static int server_handle_auth(picoquic_cnx_t *cnx,
                              uint64_t stream_id,
                              server_conn_ctx_t *conn)
{
    picoquic_connection_id_t icid;
    pcs_cid_fragment_t frag;
    pcs_auth_payload_t payload;
    uint8_t expected_hash[PCS_HASH_LEN];
    uint8_t ack_hash[PCS_HASH_LEN];
    uint8_t ack_payload[PCS_AUTH_PAYLOAD_LEN];
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
    if (payload.msg_type != PCS_MSG_CLIENT_PROOF ||
        payload.session_id != frag.session_id ||
        payload.frag_idx != frag.frag_idx ||
        payload.frag_total != frag.frag_total ||
        payload.data_len != frag.data_len) {
        return -4;
    }

    if (pcs_compute_auth_hash(conn->runtime->psk,
                              PCS_MSG_CLIENT_PROOF,
                              icid.id,
                              icid.id_len,
                              expected_hash) != 0) {
        return -5;
    }
    if (memcmp(expected_hash, payload.hash, PCS_HASH_LEN) != 0) {
        return -6;
    }

    store_rc = session_store_fragment(conn->runtime, &frag);
    if (store_rc < 0) {
        return -7;
    }

    client_list_update_from_conn(conn->runtime, cnx);
    session_emit_if_complete(conn->runtime, frag.session_id);

    if (pcs_compute_auth_hash(conn->runtime->psk,
                              PCS_MSG_SERVER_ACK,
                              icid.id,
                              icid.id_len,
                              ack_hash) != 0 ||
        pcs_build_auth_payload(PCS_MSG_SERVER_ACK,
                               &frag,
                               ack_hash,
                               ack_payload,
                               sizeof(ack_payload),
                               &ack_len) != 0) {
        return -8;
    }

    if (picoquic_add_to_stream(cnx, stream_id, ack_payload, ack_len, 1) != 0) {
        return -9;
    }

    conn->close_pending = 1;
    picoquic_set_app_wake_time(cnx, picoquic_current_time() + QS_PUSH_CLOSE_DELAY_US);

    return 0;
}

static int server_stream_callback(picoquic_cnx_t *cnx,
                                  uint64_t stream_id,
                                  uint8_t *bytes,
                                  size_t length,
                                  picoquic_call_back_event_t event,
                                  void *callback_ctx,
                                  void *stream_ctx)
{
    picoquic_quic_t *quic = picoquic_get_quic_ctx(cnx);
    server_runtime_t *runtime = (server_runtime_t *)picoquic_get_default_callback_context(quic);
    server_conn_ctx_t *conn = (server_conn_ctx_t *)callback_ctx;

    (void)stream_ctx;

    if (conn == NULL || callback_ctx == runtime) {
        conn = (server_conn_ctx_t *)calloc(1, sizeof(*conn));
        if (conn == NULL) {
            return PICOQUIC_ERROR_MEMORY;
        }
        conn->runtime = runtime;
        picoquic_set_callback(cnx, server_stream_callback, conn);
    }

    switch (event) {
    case picoquic_callback_stream_data:
    case picoquic_callback_stream_fin:
        if (stream_id != 0) {
            break;
        }
        if (length > 0U) {
            if (conn->recv_len + length > sizeof(conn->recv_buf)) {
                (void)picoquic_close(cnx, 0x201);
                return -1;
            }
            memcpy(conn->recv_buf + conn->recv_len, bytes, length);
            conn->recv_len += length;
        }

        if (event == picoquic_callback_stream_fin) {
            int rc = server_handle_auth(cnx, stream_id, conn);
            if (rc != 0) {
                (void)picoquic_close(cnx, 0x202);
                return -1;
            }
            fprintf(stdout,
                    "[server] verified uplink fragment session=0x%08x idx=%u/%u\n",
                    ((uint32_t)conn->recv_buf[6] << 24) |
                        ((uint32_t)conn->recv_buf[7] << 16) |
                        ((uint32_t)conn->recv_buf[8] << 8) |
                        (uint32_t)conn->recv_buf[9],
                    conn->recv_buf[10],
                    conn->recv_buf[11]);
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
        release_conn_ctx(cnx, conn);
        break;

    default:
        break;
    }

    return 0;
}

static int push_stream_callback(picoquic_cnx_t *cnx,
                                uint64_t stream_id,
                                uint8_t *bytes,
                                size_t length,
                                picoquic_call_back_event_t event,
                                void *callback_ctx,
                                void *stream_ctx)
{
    push_conn_ctx_t *ctx = (push_conn_ctx_t *)callback_ctx;

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
                ack.msg_type != PCS_MSG_CLIENT_PUSH_ACK ||
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

static int push_packet_loop_cb(picoquic_quic_t *quic,
                               picoquic_packet_loop_cb_enum cb_mode,
                               void *callback_ctx,
                               void *callback_arg)
{
    push_conn_ctx_t *ctx = (push_conn_ctx_t *)callback_ctx;

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

static int run_push_fragment(const server_runtime_t *runtime,
                             const char *target_ip,
                             uint16_t target_port,
                             const uint8_t *cid,
                             uint8_t cid_len,
                             const pcs_cid_fragment_t *frag)
{
    struct sockaddr_storage peer_addr;
    int is_name = 0;
    picoquic_quic_t *quic = NULL;
    picoquic_cnx_t *cnx = NULL;
    picoquic_connection_id_t initial_cid = {0};
    push_conn_ctx_t conn_ctx;
    uint8_t proof_hash[PCS_HASH_LEN];
    uint64_t now = picoquic_current_time();
    int ret;

    if (runtime == NULL || target_ip == NULL || cid == NULL || frag == NULL) {
        return -1;
    }

    memset(&peer_addr, 0, sizeof(peer_addr));
    memset(&conn_ctx, 0, sizeof(conn_ctx));
    conn_ctx.frag = *frag;

    if (picoquic_get_server_address(target_ip, target_port, &peer_addr, &is_name) != 0) {
        return -2;
    }

    if (pcs_compute_auth_hash(runtime->psk,
                              PCS_MSG_SERVER_PUSH,
                              cid,
                              cid_len,
                              proof_hash) != 0 ||
        pcs_compute_auth_hash(runtime->psk,
                              PCS_MSG_CLIENT_PUSH_ACK,
                              cid,
                              cid_len,
                              conn_ctx.expected_ack_hash) != 0 ||
        pcs_build_auth_payload(PCS_MSG_SERVER_PUSH,
                               frag,
                               proof_hash,
                               conn_ctx.proof_payload,
                               sizeof(conn_ctx.proof_payload),
                               &conn_ctx.proof_payload_len) != 0) {
        return -3;
    }

    quic = picoquic_create(1,
                           NULL,
                           NULL,
                           runtime->ca_cert,
                           runtime->alpn,
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
        return -4;
    }

    picoquic_set_null_verifier(quic);
    (void)picoquic_set_default_connection_id_length(quic, cid_len);

    initial_cid.id_len = cid_len;
    memcpy(initial_cid.id, cid, cid_len);

    cnx = picoquic_create_cnx(quic,
                              initial_cid,
                              picoquic_null_connection_id,
                              (const struct sockaddr *)&peer_addr,
                              now,
                              0,
                              (is_name && runtime->sni != NULL) ? target_ip : runtime->sni,
                              runtime->alpn,
                              1);
    if (cnx == NULL) {
        picoquic_free(quic);
        return -5;
    }

    picoquic_set_callback(cnx, push_stream_callback, &conn_ctx);

    ret = picoquic_start_client_cnx(cnx);
    if (ret != 0) {
        picoquic_free(quic);
        return -6;
    }

    ret = picoquic_packet_loop(quic,
                               0,
                               ((const struct sockaddr *)&peer_addr)->sa_family,
                               0,
                               0,
                               1,
                               push_packet_loop_cb,
                               &conn_ctx);

    picoquic_free(quic);

    if (ret == PICOQUIC_NO_ERROR_TERMINATE_PACKET_LOOP) {
        ret = 0;
    }
    if (ret != 0) {
        return -7;
    }
    if (!conn_ctx.ack_ok) {
        return -8;
    }

    return 0;
}

static int send_message_to_one(server_runtime_t *rt,
                               const char *target_ip,
                               const uint8_t *message,
                               size_t message_len)
{
    uint32_t session_id = 0;
    size_t frag_cap;
    size_t frag_total;
    size_t offset = 0;
    size_t i;

    if (rt == NULL || target_ip == NULL || message == NULL || message_len == 0U) {
        return -1;
    }

    frag_cap = pcs_cid_fragment_capacity(rt->cid_len);
    if (frag_cap == 0U) {
        return -2;
    }

    frag_total = (message_len + frag_cap - 1U) / frag_cap;
    if (frag_total > QS_MAX_FRAGMENTS) {
        return -3;
    }

    if (RAND_bytes((uint8_t *)&session_id, sizeof(session_id)) != 1) {
        session_id = (uint32_t)time(NULL);
    }

    fprintf(stdout,
            "[server] push target=%s session=0x%08x len=%zu fragments=%zu\n",
            target_ip,
            session_id,
            message_len,
            frag_total);

    for (i = 0; i < frag_total; ++i) {
        pcs_cid_fragment_t frag;
        uint8_t cid[PCS_CID_MAX_LEN];
        size_t chunk = message_len - offset;
        char cid_hex[PCS_CID_MAX_LEN * 2U + 1U];
        int rc;

        if (chunk > frag_cap) {
            chunk = frag_cap;
        }

        memset(&frag, 0, sizeof(frag));
        frag.session_id = session_id;
        frag.frag_idx = (uint8_t)i;
        frag.frag_total = (uint8_t)frag_total;
        frag.data_len = (uint8_t)chunk;
        memcpy(frag.data, message + offset, chunk);

        if (pcs_encode_cid_fragment(cid, rt->cid_len, &frag) != 0) {
            return -4;
        }

        pcs_hex_encode(cid, rt->cid_len, cid_hex, sizeof(cid_hex));
        fprintf(stdout,
                "[server] push fragment %zu/%zu to %s cid=%s\n",
                i + 1U,
                frag_total,
                target_ip,
                cid_hex);

        rc = run_push_fragment(rt,
                               target_ip,
                               rt->client_push_port,
                               cid,
                               rt->cid_len,
                               &frag);
        if (rc != 0) {
            fprintf(stderr,
                    "[server] push fragment %zu/%zu to %s failed (rc=%d)\n",
                    i + 1U,
                    frag_total,
                    target_ip,
                    rc);
            return -5;
        }

        offset += chunk;
        if (!g_stop && (i + 1U) < frag_total) {
            sleep_ms(QS_SEND_INTER_FRAG_DELAY_MS);
        }
    }

    return 0;
}

static int send_message_to_targets(server_runtime_t *rt,
                                   const char *target,
                                   const uint8_t *message,
                                   size_t message_len)
{
    push_target_t *targets = NULL;
    size_t n;
    size_t i;
    size_t ok = 0;

    n = client_list_snapshot(rt, target, &targets);
    if (n == 0U || targets == NULL) {
        fprintf(stderr, "[server] no active target matched: %s\n", target);
        return -1;
    }

    for (i = 0; i < n && !g_stop; ++i) {
        int rc = send_message_to_one(rt, targets[i].ip, message, message_len);
        if (rc == 0) {
            ok++;
        }
    }

    fprintf(stdout,
            "[server] push summary target=%s success=%zu/%zu\n",
            target,
            ok,
            n);

    free(targets);
    return (ok > 0U) ? 0 : -2;
}

static void print_cmd_help(void)
{
    fprintf(stdout,
            "[server] commands:\n"
            "  list\n"
            "  send all <message>\n"
            "  send <ip> <message>\n"
            "  help\n");
}

static void process_command(server_runtime_t *rt, char *line)
{
    char *cmd;

    if (rt == NULL || line == NULL) {
        return;
    }

    cmd = line;
    while (*cmd == ' ' || *cmd == '\t') {
        cmd++;
    }

    if (*cmd == '\0') {
        return;
    }

    if (strcmp(cmd, "list") == 0) {
        client_list_print(rt);
        return;
    }

    if (strcmp(cmd, "help") == 0) {
        print_cmd_help();
        return;
    }

    if (strncmp(cmd, "send ", 5) == 0) {
        char *target = cmd + 5;
        char *message;

        while (*target == ' ' || *target == '\t') {
            target++;
        }

        message = target;
        while (*message != '\0' && *message != ' ' && *message != '\t') {
            message++;
        }
        if (*message == '\0') {
            fprintf(stderr, "[server] invalid send command, missing message\n");
            return;
        }

        *message = '\0';
        message++;
        while (*message == ' ' || *message == '\t') {
            message++;
        }

        if (*target == '\0' || *message == '\0') {
            fprintf(stderr, "[server] invalid send command\n");
            return;
        }

        if (send_message_to_targets(rt,
                                    target,
                                    (const uint8_t *)message,
                                    strlen(message)) != 0) {
            fprintf(stderr, "[server] send command failed for target=%s\n", target);
        }
        return;
    }

    fprintf(stderr, "[server] unknown command: %s\n", cmd);
}

static void *stdin_command_thread(void *arg)
{
    server_runtime_t *rt = (server_runtime_t *)arg;

    while (!g_stop) {
        fd_set readfds;
        struct timeval tv;
        int rc;

        FD_ZERO(&readfds);
        FD_SET(STDIN_FILENO, &readfds);

        tv.tv_sec = 1;
        tv.tv_usec = 0;

        rc = select(STDIN_FILENO + 1, &readfds, NULL, NULL, &tv);
        if (rc < 0) {
            if (errno == EBADF) {
                break;
            }
            continue;
        }

        if (rc == 0) {
            continue;
        }

        if (FD_ISSET(STDIN_FILENO, &readfds)) {
            char line[QS_CMD_BUF_SIZE];
            size_t len;

            if (fgets(line, sizeof(line), stdin) == NULL) {
                if (feof(stdin)) {
                    break;
                }
                clearerr(stdin);
                continue;
            }

            len = strlen(line);
            while (len > 0U && (line[len - 1U] == '\n' || line[len - 1U] == '\r')) {
                line[len - 1U] = '\0';
                len--;
            }

            process_command(rt, line);
        }
    }

    return NULL;
}

static int server_packet_loop_cb(picoquic_quic_t *quic,
                                 picoquic_packet_loop_cb_enum cb_mode,
                                 void *callback_ctx,
                                 void *callback_arg)
{
    server_runtime_t *rt = (server_runtime_t *)callback_ctx;

    (void)quic;
    (void)callback_arg;

    switch (cb_mode) {
    case picoquic_packet_loop_ready:
        fprintf(stdout, "[server] packet loop ready\n");
        print_cmd_help();
        break;

    case picoquic_packet_loop_after_receive:
    case picoquic_packet_loop_after_send:
        if (rt != NULL) {
            time_t now_utc = time(NULL);
            pthread_mutex_lock(&rt->clients_lock);
            client_list_prune_locked(rt, now_utc);
            pthread_mutex_unlock(&rt->clients_lock);
        }
        if (g_stop) {
            return PICOQUIC_NO_ERROR_TERMINATE_PACKET_LOOP;
        }
        break;

    default:
        break;
    }

    return 0;
}

static void free_sessions(server_runtime_t *rt)
{
    server_session_t *cur = rt->sessions;

    while (cur != NULL) {
        server_session_t *next = cur->next;
        free(cur);
        cur = next;
    }
    rt->sessions = NULL;
}

static void free_clients(server_runtime_t *rt)
{
    server_client_entry_t *cur;

    pthread_mutex_lock(&rt->clients_lock);
    cur = rt->clients;
    while (cur != NULL) {
        server_client_entry_t *next = cur->next;
        free(cur);
        cur = next;
    }
    rt->clients = NULL;
    pthread_mutex_unlock(&rt->clients_lock);
}

int main(int argc, char **argv)
{
    server_opts_t opts;
    server_runtime_t runtime;
    picoquic_quic_t *quic = NULL;
    uint64_t now;
    int rc;
    int opt;
    char cert_default[PATH_MAX];
    char key_default[PATH_MAX];
    char ca_default[PATH_MAX];
    pthread_t cmd_tid;
    int cmd_thread_started = 0;

    memset(&opts, 0, sizeof(opts));
    memset(&runtime, 0, sizeof(runtime));

    snprintf(cert_default, sizeof(cert_default), "%s/certs/cert.pem", QSC_PROJECT_ROOT);
    snprintf(key_default, sizeof(key_default), "%s/certs/key.pem", QSC_PROJECT_ROOT);
    snprintf(ca_default, sizeof(ca_default), "%s/certs/cert.pem", QSC_PROJECT_ROOT);

    opts.alpn = QS_DEFAULT_ALPN;
    opts.cert_file = cert_default;
    opts.key_file = key_default;
    opts.cid_len = PCS_CID_MAX_LEN;
    opts.client_push_port = QS_DEFAULT_CLIENT_PUSH_PORT;
    opts.push_sni = QS_DEFAULT_SNI;
    opts.ca_cert = ca_default;

    while ((opt = getopt(argc, argv, "p:C:K:k:a:c:P:n:A:h")) != -1) {
        switch (opt) {
        case 'p':
            opts.port = (uint16_t)strtoul(optarg, NULL, 10);
            break;
        case 'C':
            opts.cert_file = optarg;
            break;
        case 'K':
            opts.key_file = optarg;
            break;
        case 'k':
            opts.psk_hex = optarg;
            break;
        case 'a':
            opts.alpn = optarg;
            break;
        case 'c':
            opts.cid_len = (uint8_t)strtoul(optarg, NULL, 10);
            break;
        case 'P':
            opts.client_push_port = (uint16_t)strtoul(optarg, NULL, 10);
            break;
        case 'n':
            opts.push_sni = optarg;
            break;
        case 'A':
            opts.ca_cert = optarg;
            break;
        default:
            usage(argv[0]);
            return 1;
        }
    }

    if (opts.port == 0U) {
        usage(argv[0]);
        return 1;
    }
    if (opts.cid_len < PCS_CID_MIN_LEN || opts.cid_len > PCS_CID_MAX_LEN) {
        fprintf(stderr, "invalid CID length: %u (must be 8..20)\n", opts.cid_len);
        return 1;
    }
    if (opts.client_push_port == 0U) {
        fprintf(stderr, "invalid client push port\n");
        return 1;
    }

    if (opts.psk_hex != NULL) {
        if (opts.psk_hex[0] == '\0') {
            fprintf(stderr, "empty -k value\n");
            return 1;
        }
        if (pcs_parse_psk_hex(opts.psk_hex, runtime.psk) != 0) {
            fprintf(stderr, "invalid PSK format, expected 64 hex chars\n");
            return 1;
        }
    } else {
        pcs_default_psk(runtime.psk);
    }

    runtime.cid_len = opts.cid_len;
    runtime.client_push_port = opts.client_push_port;
    runtime.alpn = opts.alpn;
    runtime.sni = opts.push_sni;
    runtime.ca_cert = opts.ca_cert;

    if (pthread_mutex_init(&runtime.clients_lock, NULL) != 0) {
        fprintf(stderr, "failed to init clients mutex\n");
        return 1;
    }

    if (signal(SIGINT, on_signal) == SIG_ERR || signal(SIGTERM, on_signal) == SIG_ERR) {
        perror("signal");
        pthread_mutex_destroy(&runtime.clients_lock);
        return 1;
    }

    now = picoquic_current_time();
    quic = picoquic_create(1024,
                           opts.cert_file,
                           opts.key_file,
                           NULL,
                           opts.alpn,
                           server_stream_callback,
                           &runtime,
                           NULL,
                           NULL,
                           NULL,
                           now,
                           NULL,
                           NULL,
                           NULL,
                           0);
    if (quic == NULL) {
        fprintf(stderr,
                "failed to create picoquic server context (cert=%s, key=%s)\n",
                opts.cert_file,
                opts.key_file);
        pthread_mutex_destroy(&runtime.clients_lock);
        return 1;
    }

    (void)picoquic_set_default_connection_id_length(quic, PCS_CID_MAX_LEN);
    picoquic_set_cookie_mode(quic, 2);

    fprintf(stdout,
            "[server] listening on UDP/%u ALPN=%s cert=%s\n",
            opts.port,
            opts.alpn,
            opts.cert_file);
    fprintf(stdout,
            "[server] push CID len=%u push-port=%u\n",
            runtime.cid_len,
            (unsigned)runtime.client_push_port);

    if (pthread_create(&cmd_tid, NULL, stdin_command_thread, &runtime) == 0) {
        cmd_thread_started = 1;
    } else {
        fprintf(stderr, "[server] warning: failed to start command thread\n");
    }

    rc = picoquic_packet_loop(quic,
                              opts.port,
                              AF_INET,
                              0,
                              0,
                              1,
                              server_packet_loop_cb,
                              &runtime);

    if (rc == PICOQUIC_NO_ERROR_TERMINATE_PACKET_LOOP) {
        rc = 0;
    }
    if (g_stop && rc == -1) {
        rc = 0;
    }
    if (rc != 0) {
        fprintf(stdout,
                "[server] packet loop exit rc=%d (%s)\n",
                rc,
                picoquic_error_name((uint64_t)rc));
    }

    g_stop = 1;
    if (cmd_thread_started) {
        (void)pthread_join(cmd_tid, NULL);
    }

    picoquic_free(quic);
    free_sessions(&runtime);
    free_clients(&runtime);
    pthread_mutex_destroy(&runtime.clients_lock);

    return (rc == 0) ? 0 : 1;
}
