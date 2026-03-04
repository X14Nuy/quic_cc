#ifndef TRAFFIC_PROFILE_H
#define TRAFFIC_PROFILE_H

#include <pthread.h>
#include <sys/types.h>
#include <stdint.h>
#include <pcap/pcap.h>

#include "alias.h"

#ifdef __cplusplus
extern "C" {
#endif

#define TP_MAX_PKT_LEN 1500U

typedef struct traffic_profile_engine_s {
    uint64_t len_hist[TP_MAX_PKT_LEN + 1];
    uint64_t *iat_hist;
    uint32_t max_iat_ms;

    alias_table_t len_alias;
    alias_table_t iat_alias;

    uint64_t pkt_seen;
    uint64_t dirty_updates;
    uint32_t rebuild_interval_packets;

    int has_last_ts;
    struct timeval last_ts;

    int running;
    pcap_t *pcap_handle;
    int datalink_type;
    pthread_t capture_tid;
    pthread_mutex_t lock;

    uint64_t rng_state;
} traffic_profile_engine_t;

/*
 * Initialize profiling engine.
 * max_iat_ms defines histogram upper bound for IAT in milliseconds.
 */
int tp_engine_init(traffic_profile_engine_t *eng,
                   uint32_t max_iat_ms,
                   uint32_t rebuild_interval_packets);

/* Stop capture thread (if running) and release all resources. */
void tp_engine_destroy(traffic_profile_engine_t *eng);

/*
 * Start continuous capture on interface.
 * bpf_filter can be NULL (default: "ip and udp").
 */
int tp_engine_start_capture(traffic_profile_engine_t *eng,
                            const char *iface,
                            const char *bpf_filter,
                            int snaplen,
                            int promisc,
                            int timeout_ms);

/* Ask capture thread to stop and wait for completion. */
void tp_engine_stop_capture(traffic_profile_engine_t *eng);

/*
 * Draw one sample pair from learned distributions.
 * If the model is still empty, returns conservative defaults.
 */
int tp_engine_sample(traffic_profile_engine_t *eng,
                     uint16_t *target_len,
                     uint32_t *next_delay_ms);

/*
 * Export normalized PDF snapshots.
 * len_pdf must have TP_MAX_PKT_LEN + 1 elements.
 * iat_pdf must have max_iat_ms + 1 elements.
 */
int tp_engine_export_pdf(traffic_profile_engine_t *eng,
                         double *len_pdf,
                         uint32_t len_pdf_n,
                         double *iat_pdf,
                         uint32_t iat_pdf_n);

uint64_t tp_engine_packet_count(traffic_profile_engine_t *eng);

#ifdef __cplusplus
}
#endif

#endif /* TRAFFIC_PROFILE_H */
