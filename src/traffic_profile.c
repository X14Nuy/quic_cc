#include "traffic_profile.h"

#include <arpa/inet.h>
#include <errno.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/time.h>

/*
 * Linux SLL (Cooked v1) header length is fixed at 16 bytes.
 * Linux SLL2 header length is fixed at 20 bytes.
 */
#define TP_SLL_V1_HDR_LEN 16U
#define TP_SLL_V2_HDR_LEN 20U

static uint64_t tp_rng_u64(void *ctx)
{
    uint64_t *state = (uint64_t *)ctx;
    uint64_t x;

    if (state == NULL) {
        return 0xDEADBEEFCAFEBABEULL;
    }
    if (*state == 0) {
        *state = 0x9E3779B97F4A7C15ULL;
    }

    x = *state;
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    *state = x;
    return x * 2685821657736338717ULL;
}

static uint64_t tp_time_diff_us(const struct timeval *a, const struct timeval *b)
{
    int64_t sec;
    int64_t usec;
    int64_t delta;

    sec = (int64_t)a->tv_sec - (int64_t)b->tv_sec;
    usec = (int64_t)a->tv_usec - (int64_t)b->tv_usec;
    delta = sec * 1000000LL + usec;
    return (delta > 0) ? (uint64_t)delta : 0ULL;
}

static int tp_extract_ipv4_udp_len(const traffic_profile_engine_t *eng,
                                   const u_char *packet,
                                   uint32_t caplen,
                                   uint16_t *pkt_len_out)
{
    uint32_t l2_len = 0;
    const struct iphdr *iph;

    if (eng == NULL || packet == NULL || pkt_len_out == NULL) {
        return -1;
    }

    switch (eng->datalink_type) {
    case DLT_EN10MB:
        if (caplen < sizeof(struct ether_header)) {
            return -1;
        }
        {
            const struct ether_header *eth = (const struct ether_header *)packet;
            if (ntohs(eth->ether_type) != ETHERTYPE_IP) {
                return -1;
            }
        }
        l2_len = sizeof(struct ether_header);
        break;

    case DLT_LINUX_SLL:
        if (caplen < TP_SLL_V1_HDR_LEN) {
            return -1;
        }
        /* Protocol field for SLL v1 is at bytes [14, 15]. */
        if (ntohs(*(const uint16_t *)(packet + 14U)) != ETHERTYPE_IP) {
            return -1;
        }
        l2_len = TP_SLL_V1_HDR_LEN;
        break;

    case DLT_LINUX_SLL2:
        if (caplen < TP_SLL_V2_HDR_LEN) {
            return -1;
        }
        /* Protocol field for SLL v2 is at bytes [0, 1]. */
        if (ntohs(*(const uint16_t *)packet) != ETHERTYPE_IP) {
            return -1;
        }
        l2_len = TP_SLL_V2_HDR_LEN;
        break;

    case DLT_RAW:
        l2_len = 0;
        break;

    default:
        /*
         * Unknown link type: fallback to wire length as coarse estimate.
         * The caller can still clamp to [0, 1500].
         */
        *pkt_len_out = (caplen > TP_MAX_PKT_LEN) ? TP_MAX_PKT_LEN : (uint16_t)caplen;
        return 0;
    }

    if (caplen < l2_len + sizeof(struct iphdr)) {
        return -1;
    }

    iph = (const struct iphdr *)(packet + l2_len);
    if (iph->version != 4 || iph->protocol != IPPROTO_UDP) {
        return -1;
    }

    {
        uint16_t ip_total_len = ntohs(iph->tot_len);
        if (ip_total_len > TP_MAX_PKT_LEN) {
            ip_total_len = TP_MAX_PKT_LEN;
        }
        *pkt_len_out = ip_total_len;
    }

    return 0;
}

static int tp_rebuild_alias_locked(traffic_profile_engine_t *eng)
{
    alias_table_t new_len = {0};
    alias_table_t new_iat = {0};
    int rc_len;
    int rc_iat;

    rc_len = alias_table_init(&new_len, eng->len_hist, TP_MAX_PKT_LEN + 1U);
    rc_iat = alias_table_init(&new_iat, eng->iat_hist, eng->max_iat_ms + 1U);

    if (rc_len != 0 || rc_iat != 0) {
        alias_table_free(&new_len);
        alias_table_free(&new_iat);
        return -1;
    }

    alias_table_free(&eng->len_alias);
    alias_table_free(&eng->iat_alias);
    eng->len_alias = new_len;
    eng->iat_alias = new_iat;
    eng->dirty_updates = 0;
    return 0;
}

static void tp_ingest_packet(traffic_profile_engine_t *eng,
                             const struct pcap_pkthdr *hdr,
                             const u_char *packet)
{
    uint16_t pkt_len = 0;
    uint32_t iat_ms = 0;

    if (eng == NULL || hdr == NULL || packet == NULL) {
        return;
    }

    if (tp_extract_ipv4_udp_len(eng, packet, hdr->caplen, &pkt_len) != 0) {
        return;
    }

    pthread_mutex_lock(&eng->lock);

    if (pkt_len > TP_MAX_PKT_LEN) {
        pkt_len = TP_MAX_PKT_LEN;
    }
    eng->len_hist[pkt_len]++;

    if (eng->has_last_ts) {
        uint64_t delta_us = tp_time_diff_us(&hdr->ts, &eng->last_ts);
        iat_ms = (uint32_t)(delta_us / 1000ULL);
        if (iat_ms > eng->max_iat_ms) {
            iat_ms = eng->max_iat_ms;
        }
        eng->iat_hist[iat_ms]++;
    }
    eng->last_ts = hdr->ts;
    eng->has_last_ts = 1;

    eng->pkt_seen++;
    eng->dirty_updates++;

    if (eng->dirty_updates >= eng->rebuild_interval_packets) {
        (void)tp_rebuild_alias_locked(eng);
    }

    pthread_mutex_unlock(&eng->lock);
}

static void tp_pcap_callback(u_char *user,
                             const struct pcap_pkthdr *hdr,
                             const u_char *packet)
{
    traffic_profile_engine_t *eng = (traffic_profile_engine_t *)user;
    tp_ingest_packet(eng, hdr, packet);
}

static void *tp_capture_thread(void *arg)
{
    traffic_profile_engine_t *eng = (traffic_profile_engine_t *)arg;

    if (eng == NULL || eng->pcap_handle == NULL) {
        return NULL;
    }

    while (eng->running) {
        int rc = pcap_dispatch(eng->pcap_handle, 128, tp_pcap_callback, (u_char *)eng);

        if (rc == PCAP_ERROR_BREAK) {
            break;
        }
        if (rc < 0) {
            fprintf(stderr, "[traffic_profile] pcap_dispatch error: %s\n",
                    pcap_geterr(eng->pcap_handle));
            break;
        }
        /* rc == 0 means timeout expired; loop again while running. */
    }

    eng->running = 0;
    return NULL;
}

int tp_engine_init(traffic_profile_engine_t *eng,
                   uint32_t max_iat_ms,
                   uint32_t rebuild_interval_packets)
{
    if (eng == NULL || max_iat_ms == 0) {
        return -1;
    }

    memset(eng, 0, sizeof(*eng));

    eng->iat_hist = (uint64_t *)calloc((size_t)max_iat_ms + 1U, sizeof(uint64_t));
    if (eng->iat_hist == NULL) {
        return -2;
    }

    if (pthread_mutex_init(&eng->lock, NULL) != 0) {
        free(eng->iat_hist);
        eng->iat_hist = NULL;
        return -3;
    }

    eng->max_iat_ms = max_iat_ms;
    eng->rebuild_interval_packets = (rebuild_interval_packets == 0U)
                                        ? 256U
                                        : rebuild_interval_packets;
    eng->rng_state = 0xA5A5A5A55A5A5A5AULL;
    return 0;
}

void tp_engine_stop_capture(traffic_profile_engine_t *eng)
{
    if (eng == NULL) {
        return;
    }

    if (!eng->running) {
        if (eng->pcap_handle != NULL) {
            pcap_close(eng->pcap_handle);
            eng->pcap_handle = NULL;
        }
        return;
    }

    eng->running = 0;
    if (eng->pcap_handle != NULL) {
        pcap_breakloop(eng->pcap_handle);
    }

    pthread_join(eng->capture_tid, NULL);

    if (eng->pcap_handle != NULL) {
        pcap_close(eng->pcap_handle);
        eng->pcap_handle = NULL;
    }
}

void tp_engine_destroy(traffic_profile_engine_t *eng)
{
    if (eng == NULL) {
        return;
    }

    tp_engine_stop_capture(eng);

    pthread_mutex_lock(&eng->lock);
    alias_table_free(&eng->len_alias);
    alias_table_free(&eng->iat_alias);
    free(eng->iat_hist);
    eng->iat_hist = NULL;
    pthread_mutex_unlock(&eng->lock);

    pthread_mutex_destroy(&eng->lock);
}

int tp_engine_start_capture(traffic_profile_engine_t *eng,
                            const char *iface,
                            const char *bpf_filter,
                            int snaplen,
                            int promisc,
                            int timeout_ms)
{
    char errbuf[PCAP_ERRBUF_SIZE] = {0};
    struct bpf_program fp = {0};
    const char *filter_expr = (bpf_filter == NULL) ? "ip and udp" : bpf_filter;

    if (eng == NULL || iface == NULL) {
        return -1;
    }
    if (eng->running) {
        return -2;
    }

    eng->pcap_handle = pcap_open_live(iface, snaplen, promisc, timeout_ms, errbuf);
    if (eng->pcap_handle == NULL) {
        fprintf(stderr, "[traffic_profile] pcap_open_live(%s) failed: %s\n", iface, errbuf);
        return -3;
    }

    eng->datalink_type = pcap_datalink(eng->pcap_handle);

    if (pcap_compile(eng->pcap_handle, &fp, filter_expr, 1, PCAP_NETMASK_UNKNOWN) != 0) {
        fprintf(stderr, "[traffic_profile] pcap_compile failed: %s\n",
                pcap_geterr(eng->pcap_handle));
        pcap_close(eng->pcap_handle);
        eng->pcap_handle = NULL;
        return -4;
    }

    if (pcap_setfilter(eng->pcap_handle, &fp) != 0) {
        fprintf(stderr, "[traffic_profile] pcap_setfilter failed: %s\n",
                pcap_geterr(eng->pcap_handle));
        pcap_freecode(&fp);
        pcap_close(eng->pcap_handle);
        eng->pcap_handle = NULL;
        return -5;
    }
    pcap_freecode(&fp);

    eng->running = 1;
    if (pthread_create(&eng->capture_tid, NULL, tp_capture_thread, eng) != 0) {
        eng->running = 0;
        pcap_close(eng->pcap_handle);
        eng->pcap_handle = NULL;
        return -6;
    }

    return 0;
}

int tp_engine_sample(traffic_profile_engine_t *eng,
                     uint16_t *target_len,
                     uint32_t *next_delay_ms)
{
    if (eng == NULL || target_len == NULL || next_delay_ms == NULL) {
        return -1;
    }

    pthread_mutex_lock(&eng->lock);

    if (eng->dirty_updates > 0 && eng->dirty_updates >= eng->rebuild_interval_packets) {
        (void)tp_rebuild_alias_locked(eng);
    }

    if (eng->len_alias.n == 0 || eng->iat_alias.n == 0) {
        /*
         * Conservative fallback for early-stage sampling before enough packets
         * are observed to build stable distributions.
         */
        *target_len = 1200U;
        *next_delay_ms = 10U;
        pthread_mutex_unlock(&eng->lock);
        return 0;
    }

    *target_len = (uint16_t)alias_table_sample(&eng->len_alias, tp_rng_u64, &eng->rng_state);
    *next_delay_ms = (uint32_t)alias_table_sample(&eng->iat_alias, tp_rng_u64, &eng->rng_state);

    pthread_mutex_unlock(&eng->lock);
    return 0;
}

int tp_engine_export_pdf(traffic_profile_engine_t *eng,
                         double *len_pdf,
                         uint32_t len_pdf_n,
                         double *iat_pdf,
                         uint32_t iat_pdf_n)
{
    uint64_t len_sum = 0;
    uint64_t iat_sum = 0;
    uint32_t i;

    if (eng == NULL || len_pdf == NULL || iat_pdf == NULL) {
        return -1;
    }
    if (len_pdf_n < (TP_MAX_PKT_LEN + 1U) || iat_pdf_n < (eng->max_iat_ms + 1U)) {
        return -2;
    }

    pthread_mutex_lock(&eng->lock);

    for (i = 0; i <= TP_MAX_PKT_LEN; ++i) {
        len_sum += eng->len_hist[i];
    }
    for (i = 0; i <= eng->max_iat_ms; ++i) {
        iat_sum += eng->iat_hist[i];
    }

    for (i = 0; i <= TP_MAX_PKT_LEN; ++i) {
        len_pdf[i] = (len_sum == 0) ? 0.0 : (double)eng->len_hist[i] / (double)len_sum;
    }
    for (i = 0; i <= eng->max_iat_ms; ++i) {
        iat_pdf[i] = (iat_sum == 0) ? 0.0 : (double)eng->iat_hist[i] / (double)iat_sum;
    }

    pthread_mutex_unlock(&eng->lock);
    return 0;
}

uint64_t tp_engine_packet_count(traffic_profile_engine_t *eng)
{
    uint64_t count;

    if (eng == NULL) {
        return 0;
    }

    pthread_mutex_lock(&eng->lock);
    count = eng->pkt_seen;
    pthread_mutex_unlock(&eng->lock);

    return count;
}
