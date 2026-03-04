#ifndef MICROBURST_SCHEDULER_H
#define MICROBURST_SCHEDULER_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct microburst_scheduler_s microburst_scheduler_t;

typedef struct microburst_scheduler_cfg_s {
    const char *iface;
    const char *profile_bpf;
    const char *trigger_bpf;
    const char *dst_ip;
    uint16_t dst_port;

    uint16_t cid_len;
    uint32_t max_iat_ms;
    uint32_t alias_rebuild_interval;

    uint32_t microburst_packets;
    uint32_t trigger_window_ms;
    uint32_t trigger_pkt_threshold;
    uint32_t trigger_cooldown_ms;
} microburst_scheduler_cfg_t;

int mbs_create(microburst_scheduler_t **out, const microburst_scheduler_cfg_t *cfg);
void mbs_destroy(microburst_scheduler_t *sch);

int mbs_set_entropy(microburst_scheduler_t *sch,
                    const uint8_t *entropy,
                    size_t entropy_len);

int mbs_start(microburst_scheduler_t *sch);
void mbs_stop(microburst_scheduler_t *sch);

#ifdef __cplusplus
}
#endif

#endif /* MICROBURST_SCHEDULER_H */
