#ifndef PICO_CID_SECURE_H
#define PICO_CID_SECURE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PCS_PSK_LEN 32U
#define PCS_HASH_LEN 32U

#define PCS_CID_MAX_LEN 20U
#define PCS_CID_MIN_LEN 8U
#define PCS_CID_MAGIC 0xA7U

#define PCS_AUTH_VERSION 1U
#define PCS_MSG_CLIENT_PROOF 1U
#define PCS_MSG_SERVER_ACK 2U
#define PCS_MSG_SERVER_PUSH 3U
#define PCS_MSG_CLIENT_PUSH_ACK 4U

#define PCS_AUTH_PAYLOAD_LEN 45U

typedef struct pcs_cid_fragment_s {
    uint32_t session_id;
    uint8_t frag_idx;
    uint8_t frag_total;
    uint8_t data_len;
    uint8_t data[PCS_CID_MAX_LEN];
} pcs_cid_fragment_t;

typedef struct pcs_auth_payload_s {
    uint8_t version;
    uint8_t msg_type;
    uint32_t session_id;
    uint8_t frag_idx;
    uint8_t frag_total;
    uint8_t data_len;
    uint8_t hash[PCS_HASH_LEN];
} pcs_auth_payload_t;

int pcs_parse_psk_hex(const char *hex, uint8_t out_psk[PCS_PSK_LEN]);
void pcs_default_psk(uint8_t out_psk[PCS_PSK_LEN]);

size_t pcs_cid_fragment_capacity(uint8_t cid_len);

int pcs_encode_cid_fragment(uint8_t *cid,
                            uint8_t cid_len,
                            const pcs_cid_fragment_t *frag);

int pcs_decode_cid_fragment(const uint8_t *cid,
                            size_t cid_len,
                            pcs_cid_fragment_t *frag_out);

int pcs_compute_auth_hash(const uint8_t psk[PCS_PSK_LEN],
                          uint8_t msg_type,
                          const uint8_t *cid,
                          size_t cid_len,
                          uint8_t out_hash[PCS_HASH_LEN]);

int pcs_build_auth_payload(uint8_t msg_type,
                           const pcs_cid_fragment_t *frag,
                           const uint8_t hash[PCS_HASH_LEN],
                           uint8_t *out,
                           size_t out_cap,
                           size_t *out_len);

int pcs_parse_auth_payload(const uint8_t *in,
                           size_t in_len,
                           pcs_auth_payload_t *out);

void pcs_hex_encode(const uint8_t *in, size_t in_len, char *out, size_t out_cap);

#ifdef __cplusplus
}
#endif

#endif /* PICO_CID_SECURE_H */
