#ifndef QUIC_CID_H
#define QUIC_CID_H

#include <pthread.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define QUIC_CID_MAX_LEN 20U

typedef struct quic_cid_injector_s {
    uint8_t *entropy;
    size_t entropy_len;
    size_t cursor;
    uint64_t prng_state;
    pthread_mutex_t lock;
} quic_cid_injector_t;

/* Initialize/destroy injector context. */
int quic_cid_injector_init(quic_cid_injector_t *inj);
void quic_cid_injector_destroy(quic_cid_injector_t *inj);

/*
 * Update external high-entropy byte stream.
 * Data is copied into injector-owned memory.
 */
int quic_cid_set_entropy(quic_cid_injector_t *inj,
                         const uint8_t *entropy,
                         size_t entropy_len);

/*
 * Generate CID bytes for QUIC long-header DCID/SCID fields.
 * cid_len must satisfy 1..20 for interoperable QUIC usage.
 */
int quic_cid_generate(quic_cid_injector_t *inj, uint8_t *out, size_t cid_len);

/*
 * In-place overwrite of QUIC Initial DCID.
 * Safety constraint: replacement length must match existing DCID length.
 */
int quic_initial_patch_dcid_inplace(uint8_t *packet,
                                    size_t packet_len,
                                    const uint8_t *new_dcid,
                                    size_t new_dcid_len);

/* Fill arbitrary bytes with injector entropy policy (used by Module C padding). */
int quic_entropy_fill(quic_cid_injector_t *inj, uint8_t *out, size_t out_len);

#ifdef __cplusplus
}
#endif

#endif /* QUIC_CID_H */
