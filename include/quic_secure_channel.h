#ifndef QUIC_SECURE_CHANNEL_H
#define QUIC_SECURE_CHANNEL_H

#include <stddef.h>
#include <stdint.h>

#include "quic_cid.h"
#include "traffic_profile.h"

#ifdef __cplusplus
extern "C" {
#endif

#define QSC_MAX_TEXT_LEN 1024U

typedef enum qsc_msg_type_e {
    QSC_MSG_HELLO = 1,
    QSC_MSG_HELLO_ACK = 2,
    QSC_MSG_DATA = 3,
    QSC_MSG_DATA_ACK = 4,
    QSC_MSG_BYE = 5,
    QSC_MSG_BYE_ACK = 6
} qsc_msg_type_t;

typedef struct qsc_config_s {
    const char *iface;
    const char *profile_bpf;
    uint32_t max_iat_ms;
    uint32_t alias_rebuild_interval;
    uint16_t cid_len;
    const char *psk_hex; /* Optional 64-hex-char key; fallback to built-in key if NULL. */
} qsc_config_t;

typedef struct qsc_context_s {
    traffic_profile_engine_t profile;
    quic_cid_injector_t injector;

    int profile_initialized;
    int profile_enabled;
    int injector_initialized;

    uint16_t cid_len;
    uint8_t psk[32];
    uint32_t tx_packet_number;
} qsc_context_t;

typedef struct qsc_message_s {
    uint8_t msg_type;
    uint32_t seq;

    int cid_meta_valid;
    uint8_t cid_msg_type;
    uint32_t cid_seq;

    uint16_t text_len;
    uint8_t text[QSC_MAX_TEXT_LEN];
} qsc_message_t;

int qsc_context_init(qsc_context_t *ctx, const qsc_config_t *cfg);
void qsc_context_destroy(qsc_context_t *ctx);
const char *qsc_context_init_error(int rc);

int qsc_set_entropy(qsc_context_t *ctx, const uint8_t *entropy, size_t entropy_len);

/*
 * Build one encrypted QUIC-like long-header packet.
 *
 * applied_target_len returns the final datagram length after dynamic padding.
 * next_delay_ms returns sampled delay from traffic model (for sender pacing).
 */
int qsc_prepare_packet(qsc_context_t *ctx,
                       uint8_t msg_type,
                       uint32_t seq,
                       const uint8_t *text,
                       uint16_t text_len,
                       uint8_t *out_packet,
                       size_t out_cap,
                       size_t *out_len,
                       uint16_t *applied_target_len,
                       uint32_t *next_delay_ms);

int qsc_parse_packet(qsc_context_t *ctx,
                     const uint8_t *packet,
                     size_t packet_len,
                     qsc_message_t *msg_out);

const char *qsc_msg_type_name(uint8_t msg_type);
void qsc_sleep_ms(uint32_t ms);

#ifdef __cplusplus
}
#endif

#endif /* QUIC_SECURE_CHANNEL_H */
