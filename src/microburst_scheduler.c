#include "microburst_scheduler.h"

#include <arpa/inet.h>
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <pcap/pcap.h>

#include "quic_cid.h"
#include "traffic_profile.h"

#define MBS_DEFAULT_PROFILE_BPF "ip and udp"
#define MBS_DEFAULT_TRIGGER_BPF "ip and udp"
#define MBS_MAX_PACKET_SIZE 1600U
#define MBS_INITIAL_MIN_SIZE 1200U

struct microburst_scheduler_s {
    microburst_scheduler_cfg_t cfg;

    char *iface;
    char *profile_bpf;
    char *trigger_bpf;
    char *dst_ip;

    int running;
    int sender_started;
    int monitor_started;

    int udp_sock;
    struct sockaddr_in dst_addr;

    pcap_t *monitor_pcap;
    pthread_t monitor_tid;
    pthread_t sender_tid;

    traffic_profile_engine_t profile;
    quic_cid_injector_t injector;

    pthread_mutex_t lock;
    pthread_cond_t cond;
    int lock_initialized;
    int cond_initialized;
    int profile_initialized;
    int injector_initialized;
    int trigger_pending;
    uint64_t last_trigger_ms;

    uint64_t *event_ms;
    uint32_t event_cap;
    uint32_t event_head;
    uint32_t event_count;

    uint32_t packet_number;
};

static char *mbs_strdup(const char *s)
{
    size_t n;
    char *out;

    if (s == NULL) {
        return NULL;
    }

    n = strlen(s) + 1U;
    out = (char *)malloc(n);
    if (out == NULL) {
        return NULL;
    }
    memcpy(out, s, n);
    return out;
}

static uint64_t monotonic_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static void sleep_ms(uint32_t ms)
{
    struct timespec req;

    req.tv_sec = (time_t)(ms / 1000U);
    req.tv_nsec = (long)((ms % 1000U) * 1000000UL);

    while (nanosleep(&req, &req) == -1 && errno == EINTR) {
        /* Continue sleeping for the remaining interval. */
    }
}

static size_t quic_varint_len(uint64_t v)
{
    if (v < (1ULL << 6)) {
        return 1;
    }
    if (v < (1ULL << 14)) {
        return 2;
    }
    if (v < (1ULL << 30)) {
        return 4;
    }
    if (v < (1ULL << 62)) {
        return 8;
    }
    return 0;
}

static int quic_varint_encode(uint64_t v, uint8_t *out, size_t out_cap, size_t *written)
{
    size_t n = quic_varint_len(v);

    if (out == NULL || written == NULL || n == 0 || out_cap < n) {
        return -1;
    }

    if (n == 1) {
        out[0] = (uint8_t)(v & 0x3FU);
    } else if (n == 2) {
        out[0] = (uint8_t)(0x40U | ((v >> 8) & 0x3FU));
        out[1] = (uint8_t)(v & 0xFFU);
    } else if (n == 4) {
        out[0] = (uint8_t)(0x80U | ((v >> 24) & 0x3FU));
        out[1] = (uint8_t)((v >> 16) & 0xFFU);
        out[2] = (uint8_t)((v >> 8) & 0xFFU);
        out[3] = (uint8_t)(v & 0xFFU);
    } else {
        out[0] = (uint8_t)(0xC0U | ((v >> 56) & 0x3FU));
        out[1] = (uint8_t)((v >> 48) & 0xFFU);
        out[2] = (uint8_t)((v >> 40) & 0xFFU);
        out[3] = (uint8_t)((v >> 32) & 0xFFU);
        out[4] = (uint8_t)((v >> 24) & 0xFFU);
        out[5] = (uint8_t)((v >> 16) & 0xFFU);
        out[6] = (uint8_t)((v >> 8) & 0xFFU);
        out[7] = (uint8_t)(v & 0xFFU);
    }

    *written = n;
    return 0;
}

static int build_quic_initial_packet(microburst_scheduler_t *sch,
                                     uint8_t *packet,
                                     size_t packet_cap,
                                     uint16_t target_len,
                                     size_t *out_len)
{
    static const uint8_t marker[] = {'M', 'B', 'U', 'R', 'S', 'T', 'v', '1'};
    uint8_t dcid[QUIC_CID_MAX_LEN];
    uint8_t scid[8];
    const uint8_t pn_len = 2;
    uint64_t quic_len = 0;
    size_t len_field_bytes = 0;
    size_t base_without_len;
    size_t payload_len;
    size_t marker_copy;
    size_t off = 0;
    size_t i;

    if (sch == NULL || packet == NULL || out_len == NULL) {
        return -1;
    }

    if (target_len < MBS_INITIAL_MIN_SIZE) {
        target_len = MBS_INITIAL_MIN_SIZE;
    }
    if (target_len > packet_cap) {
        return -2;
    }

    if (quic_cid_generate(&sch->injector, dcid, sch->cfg.cid_len) != 0) {
        return -3;
    }
    if (quic_entropy_fill(&sch->injector, scid, sizeof(scid)) != 0) {
        return -4;
    }

    /*
     * QUIC Initial header layout (long header):
     * [type/version][DCID len + DCID][SCID len + SCID][token_len][length][PN][payload]
     */
    base_without_len = 1U + 4U + 1U + sch->cfg.cid_len + 1U + sizeof(scid) + 1U;

    for (i = 0; i < 3U; ++i) {
        size_t candidate = (i == 0U) ? 1U : (i == 1U ? 2U : 4U);
        if ((size_t)target_len <= base_without_len + candidate + pn_len) {
            continue;
        }
        quic_len = (uint64_t)target_len - (uint64_t)base_without_len - (uint64_t)candidate;
        if (quic_varint_len(quic_len) == candidate) {
            len_field_bytes = candidate;
            break;
        }
    }

    if (len_field_bytes == 0U || quic_len < pn_len) {
        return -5;
    }

    payload_len = (size_t)(quic_len - pn_len);

    packet[off++] = 0xC1U; /* Long header + fixed bit + Initial type + PN length=2. */
    packet[off++] = 0x00U;
    packet[off++] = 0x00U;
    packet[off++] = 0x00U;
    packet[off++] = 0x01U; /* QUIC v1 */

    packet[off++] = (uint8_t)sch->cfg.cid_len;
    memcpy(packet + off, dcid, sch->cfg.cid_len);
    off += sch->cfg.cid_len;

    packet[off++] = (uint8_t)sizeof(scid);
    memcpy(packet + off, scid, sizeof(scid));
    off += sizeof(scid);

    packet[off++] = 0x00U; /* token length varint = 0 */

    {
        size_t written = 0;
        if (quic_varint_encode(quic_len, packet + off, packet_cap - off, &written) != 0) {
            return -6;
        }
        off += written;
    }

    packet[off++] = (uint8_t)((sch->packet_number >> 8) & 0xFFU);
    packet[off++] = (uint8_t)(sch->packet_number & 0xFFU);
    sch->packet_number++;

    marker_copy = (payload_len < sizeof(marker)) ? payload_len : sizeof(marker);
    if (marker_copy > 0U) {
        memcpy(packet + off, marker, marker_copy);
        off += marker_copy;
    }

    if (payload_len > marker_copy) {
        size_t pad_len = payload_len - marker_copy;
        if (quic_entropy_fill(&sch->injector, packet + off, pad_len) != 0) {
            return -7;
        }
        off += pad_len;
    }

    *out_len = off;
    return (off == (size_t)target_len) ? 0 : -8;
}

static void event_push(microburst_scheduler_t *sch, uint64_t ts_ms)
{
    uint32_t pos;

    if (sch->event_cap == 0) {
        return;
    }

    if (sch->event_count < sch->event_cap) {
        pos = (sch->event_head + sch->event_count) % sch->event_cap;
        sch->event_ms[pos] = ts_ms;
        sch->event_count++;
        return;
    }

    /* Queue full: overwrite oldest and advance head. */
    sch->event_ms[sch->event_head] = ts_ms;
    sch->event_head = (sch->event_head + 1U) % sch->event_cap;
}

static uint64_t event_peek_oldest(const microburst_scheduler_t *sch)
{
    return sch->event_ms[sch->event_head];
}

static void event_pop_oldest(microburst_scheduler_t *sch)
{
    if (sch->event_count == 0) {
        return;
    }

    sch->event_head = (sch->event_head + 1U) % sch->event_cap;
    sch->event_count--;
}

static void monitor_callback(u_char *user,
                             const struct pcap_pkthdr *hdr,
                             const u_char *packet)
{
    microburst_scheduler_t *sch = (microburst_scheduler_t *)user;
    uint64_t now_ms;

    (void)packet;

    if (sch == NULL || hdr == NULL) {
        return;
    }

    now_ms = (uint64_t)hdr->ts.tv_sec * 1000ULL + (uint64_t)hdr->ts.tv_usec / 1000ULL;

    pthread_mutex_lock(&sch->lock);

    event_push(sch, now_ms);
    while (sch->event_count > 0) {
        uint64_t oldest = event_peek_oldest(sch);
        if (now_ms < oldest || now_ms - oldest <= sch->cfg.trigger_window_ms) {
            break;
        }
        event_pop_oldest(sch);
    }

    if (sch->event_count >= sch->cfg.trigger_pkt_threshold) {
        if (sch->last_trigger_ms == 0 || now_ms < sch->last_trigger_ms ||
            now_ms - sch->last_trigger_ms >= sch->cfg.trigger_cooldown_ms) {
            sch->trigger_pending = 1;
            sch->last_trigger_ms = now_ms;
            pthread_cond_signal(&sch->cond);
        }
    }

    pthread_mutex_unlock(&sch->lock);
}

static void *monitor_thread_main(void *arg)
{
    microburst_scheduler_t *sch = (microburst_scheduler_t *)arg;

    while (sch->running) {
        int rc = pcap_dispatch(sch->monitor_pcap, 128, monitor_callback, (u_char *)sch);
        if (rc == PCAP_ERROR_BREAK) {
            break;
        }
        if (rc < 0) {
            fprintf(stderr, "[module C] monitor pcap error: %s\n",
                    pcap_geterr(sch->monitor_pcap));
            break;
        }
    }

    return NULL;
}

static void *sender_thread_main(void *arg)
{
    microburst_scheduler_t *sch = (microburst_scheduler_t *)arg;

    while (1) {
        uint32_t i;

        pthread_mutex_lock(&sch->lock);
        while (sch->running && !sch->trigger_pending) {
            pthread_cond_wait(&sch->cond, &sch->lock);
        }
        if (!sch->running) {
            pthread_mutex_unlock(&sch->lock);
            break;
        }
        sch->trigger_pending = 0;
        pthread_mutex_unlock(&sch->lock);

        for (i = 0; i < sch->cfg.microburst_packets; ++i) {
            uint16_t target_len = 0;
            uint32_t delay_ms = 0;
            uint8_t packet[MBS_MAX_PACKET_SIZE];
            size_t packet_len = 0;

            if (!sch->running) {
                break;
            }

            if (tp_engine_sample(&sch->profile, &target_len, &delay_ms) != 0) {
                target_len = MBS_INITIAL_MIN_SIZE;
                delay_ms = 10;
            }
            if (target_len > 1500U) {
                target_len = 1500U;
            }

            if (build_quic_initial_packet(sch, packet, sizeof(packet), target_len, &packet_len) != 0) {
                continue;
            }

            if (sendto(sch->udp_sock,
                       packet,
                       packet_len,
                       0,
                       (const struct sockaddr *)&sch->dst_addr,
                       sizeof(sch->dst_addr)) < 0) {
                perror("[module C] sendto");
                break;
            }

            if (i + 1U < sch->cfg.microburst_packets) {
                sleep_ms(delay_ms);
            }
        }
    }

    return NULL;
}

int mbs_create(microburst_scheduler_t **out, const microburst_scheduler_cfg_t *cfg)
{
    microburst_scheduler_t *sch;

    if (out == NULL || cfg == NULL || cfg->iface == NULL || cfg->dst_ip == NULL ||
        cfg->dst_port == 0U) {
        return -1;
    }

    sch = (microburst_scheduler_t *)calloc(1, sizeof(*sch));
    if (sch == NULL) {
        return -2;
    }

    sch->iface = mbs_strdup(cfg->iface);
    sch->profile_bpf = mbs_strdup(cfg->profile_bpf ? cfg->profile_bpf : MBS_DEFAULT_PROFILE_BPF);
    sch->trigger_bpf = mbs_strdup(cfg->trigger_bpf ? cfg->trigger_bpf : MBS_DEFAULT_TRIGGER_BPF);
    sch->dst_ip = mbs_strdup(cfg->dst_ip);

    if (sch->iface == NULL || sch->profile_bpf == NULL ||
        sch->trigger_bpf == NULL || sch->dst_ip == NULL) {
        mbs_destroy(sch);
        return -3;
    }

    sch->cfg = *cfg;
    sch->cfg.cid_len = (cfg->cid_len == 0U) ? 16U : cfg->cid_len;
    if (sch->cfg.cid_len > QUIC_CID_MAX_LEN) {
        sch->cfg.cid_len = QUIC_CID_MAX_LEN;
    }
    sch->cfg.max_iat_ms = (cfg->max_iat_ms == 0U) ? 5000U : cfg->max_iat_ms;
    sch->cfg.alias_rebuild_interval = (cfg->alias_rebuild_interval == 0U)
                                          ? 256U
                                          : cfg->alias_rebuild_interval;
    sch->cfg.microburst_packets = (cfg->microburst_packets == 0U) ? 8U : cfg->microburst_packets;
    sch->cfg.trigger_window_ms = (cfg->trigger_window_ms == 0U) ? 200U : cfg->trigger_window_ms;
    sch->cfg.trigger_pkt_threshold = (cfg->trigger_pkt_threshold == 0U)
                                         ? 20U
                                         : cfg->trigger_pkt_threshold;
    sch->cfg.trigger_cooldown_ms = (cfg->trigger_cooldown_ms == 0U)
                                       ? 500U
                                       : cfg->trigger_cooldown_ms;

    sch->event_cap = sch->cfg.trigger_pkt_threshold * 16U + 1024U;
    sch->event_ms = (uint64_t *)calloc(sch->event_cap, sizeof(uint64_t));
    if (sch->event_ms == NULL) {
        mbs_destroy(sch);
        return -4;
    }

    if (pthread_mutex_init(&sch->lock, NULL) != 0) {
        mbs_destroy(sch);
        return -5;
    }
    sch->lock_initialized = 1;

    if (pthread_cond_init(&sch->cond, NULL) != 0) {
        mbs_destroy(sch);
        return -5;
    }
    sch->cond_initialized = 1;

    if (tp_engine_init(&sch->profile, sch->cfg.max_iat_ms, sch->cfg.alias_rebuild_interval) != 0) {
        mbs_destroy(sch);
        return -6;
    }
    sch->profile_initialized = 1;

    if (quic_cid_injector_init(&sch->injector) != 0) {
        mbs_destroy(sch);
        return -7;
    }
    sch->injector_initialized = 1;

    sch->udp_sock = -1;
    *out = sch;
    return 0;
}

int mbs_set_entropy(microburst_scheduler_t *sch,
                    const uint8_t *entropy,
                    size_t entropy_len)
{
    if (sch == NULL) {
        return -1;
    }
    return quic_cid_set_entropy(&sch->injector, entropy, entropy_len);
}

int mbs_start(microburst_scheduler_t *sch)
{
    struct bpf_program fp = {0};
    char errbuf[PCAP_ERRBUF_SIZE] = {0};

    if (sch == NULL) {
        return -1;
    }
    if (sch->running) {
        return -2;
    }

    if (tp_engine_start_capture(&sch->profile,
                                sch->iface,
                                sch->profile_bpf,
                                2048,
                                1,
                                100) != 0) {
        return -3;
    }

    sch->udp_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sch->udp_sock < 0) {
        tp_engine_stop_capture(&sch->profile);
        return -4;
    }

    memset(&sch->dst_addr, 0, sizeof(sch->dst_addr));
    sch->dst_addr.sin_family = AF_INET;
    sch->dst_addr.sin_port = htons(sch->cfg.dst_port);
    if (inet_pton(AF_INET, sch->dst_ip, &sch->dst_addr.sin_addr) != 1) {
        close(sch->udp_sock);
        sch->udp_sock = -1;
        tp_engine_stop_capture(&sch->profile);
        return -5;
    }

    sch->monitor_pcap = pcap_open_live(sch->iface, 2048, 1, 100, errbuf);
    if (sch->monitor_pcap == NULL) {
        close(sch->udp_sock);
        sch->udp_sock = -1;
        tp_engine_stop_capture(&sch->profile);
        fprintf(stderr, "[module C] pcap_open_live monitor failed: %s\n", errbuf);
        return -6;
    }

    if (pcap_compile(sch->monitor_pcap, &fp, sch->trigger_bpf, 1, PCAP_NETMASK_UNKNOWN) != 0 ||
        pcap_setfilter(sch->monitor_pcap, &fp) != 0) {
        pcap_freecode(&fp);
        pcap_close(sch->monitor_pcap);
        sch->monitor_pcap = NULL;
        close(sch->udp_sock);
        sch->udp_sock = -1;
        tp_engine_stop_capture(&sch->profile);
        return -7;
    }
    pcap_freecode(&fp);

    sch->running = 1;
    sch->packet_number = (uint32_t)(monotonic_ns() & 0xFFFFU);

    if (pthread_create(&sch->sender_tid, NULL, sender_thread_main, sch) != 0) {
        sch->running = 0;
        pcap_close(sch->monitor_pcap);
        sch->monitor_pcap = NULL;
        close(sch->udp_sock);
        sch->udp_sock = -1;
        tp_engine_stop_capture(&sch->profile);
        return -8;
    }
    sch->sender_started = 1;

    if (pthread_create(&sch->monitor_tid, NULL, monitor_thread_main, sch) != 0) {
        sch->running = 0;
        pthread_cond_signal(&sch->cond);
        pthread_join(sch->sender_tid, NULL);
        sch->sender_started = 0;
        pcap_close(sch->monitor_pcap);
        sch->monitor_pcap = NULL;
        close(sch->udp_sock);
        sch->udp_sock = -1;
        tp_engine_stop_capture(&sch->profile);
        return -9;
    }
    sch->monitor_started = 1;

    return 0;
}

void mbs_stop(microburst_scheduler_t *sch)
{
    if (sch == NULL) {
        return;
    }

    if (!sch->running) {
        return;
    }

    sch->running = 0;

    if (sch->monitor_pcap != NULL) {
        pcap_breakloop(sch->monitor_pcap);
    }

    pthread_mutex_lock(&sch->lock);
    pthread_cond_broadcast(&sch->cond);
    pthread_mutex_unlock(&sch->lock);

    if (sch->monitor_started) {
        pthread_join(sch->monitor_tid, NULL);
        sch->monitor_started = 0;
    }
    if (sch->sender_started) {
        pthread_join(sch->sender_tid, NULL);
        sch->sender_started = 0;
    }

    if (sch->monitor_pcap != NULL) {
        pcap_close(sch->monitor_pcap);
        sch->monitor_pcap = NULL;
    }

    if (sch->udp_sock >= 0) {
        close(sch->udp_sock);
        sch->udp_sock = -1;
    }

    tp_engine_stop_capture(&sch->profile);
}

void mbs_destroy(microburst_scheduler_t *sch)
{
    if (sch == NULL) {
        return;
    }

    mbs_stop(sch);

    if (sch->injector_initialized) {
        quic_cid_injector_destroy(&sch->injector);
        sch->injector_initialized = 0;
    }
    if (sch->profile_initialized) {
        tp_engine_destroy(&sch->profile);
        sch->profile_initialized = 0;
    }

    if (sch->cond_initialized) {
        pthread_cond_destroy(&sch->cond);
        sch->cond_initialized = 0;
    }
    if (sch->lock_initialized) {
        pthread_mutex_destroy(&sch->lock);
        sch->lock_initialized = 0;
    }

    free(sch->event_ms);
    free(sch->iface);
    free(sch->profile_bpf);
    free(sch->trigger_bpf);
    free(sch->dst_ip);
    free(sch);
}
