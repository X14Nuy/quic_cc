#include "quic_cid.h"

#include <stdlib.h>
#include <string.h>

static uint64_t qc_prng_u64(uint64_t *state)
{
    uint64_t x;

    if (state == NULL) {
        return 0x0123456789ABCDEFULL;
    }
    if (*state == 0) {
        *state = 0xF00DBAADCAFED00DULL;
    }

    x = *state;
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    *state = x;
    return x * 2685821657736338717ULL;
}

static uint8_t qc_next_entropy_byte(quic_cid_injector_t *inj)
{
    uint8_t byte;

    if (inj->entropy != NULL && inj->entropy_len > 0) {
        byte = inj->entropy[inj->cursor % inj->entropy_len];
        inj->cursor++;
        return byte;
    }

    return (uint8_t)(qc_prng_u64(&inj->prng_state) & 0xFFU);
}

int quic_cid_injector_init(quic_cid_injector_t *inj)
{
    if (inj == NULL) {
        return -1;
    }

    memset(inj, 0, sizeof(*inj));
    inj->prng_state = 0xBADC0FFEE0DDF00DULL;

    if (pthread_mutex_init(&inj->lock, NULL) != 0) {
        return -2;
    }
    return 0;
}

void quic_cid_injector_destroy(quic_cid_injector_t *inj)
{
    if (inj == NULL) {
        return;
    }

    pthread_mutex_lock(&inj->lock);
    free(inj->entropy);
    inj->entropy = NULL;
    inj->entropy_len = 0;
    inj->cursor = 0;
    pthread_mutex_unlock(&inj->lock);

    pthread_mutex_destroy(&inj->lock);
}

int quic_cid_set_entropy(quic_cid_injector_t *inj,
                         const uint8_t *entropy,
                         size_t entropy_len)
{
    uint8_t *copy;

    if (inj == NULL || entropy == NULL || entropy_len == 0) {
        return -1;
    }

    copy = (uint8_t *)malloc(entropy_len);
    if (copy == NULL) {
        return -2;
    }
    memcpy(copy, entropy, entropy_len);

    pthread_mutex_lock(&inj->lock);
    free(inj->entropy);
    inj->entropy = copy;
    inj->entropy_len = entropy_len;
    inj->cursor = 0;
    pthread_mutex_unlock(&inj->lock);

    return 0;
}

int quic_entropy_fill(quic_cid_injector_t *inj, uint8_t *out, size_t out_len)
{
    size_t i;

    if (inj == NULL || out == NULL) {
        return -1;
    }

    pthread_mutex_lock(&inj->lock);
    for (i = 0; i < out_len; ++i) {
        out[i] = qc_next_entropy_byte(inj);
    }
    pthread_mutex_unlock(&inj->lock);

    return 0;
}

int quic_cid_generate(quic_cid_injector_t *inj, uint8_t *out, size_t cid_len)
{
    if (inj == NULL || out == NULL || cid_len == 0 || cid_len > QUIC_CID_MAX_LEN) {
        return -1;
    }

    return quic_entropy_fill(inj, out, cid_len);
}

int quic_initial_patch_dcid_inplace(uint8_t *packet,
                                    size_t packet_len,
                                    const uint8_t *new_dcid,
                                    size_t new_dcid_len)
{
    uint8_t first;
    uint8_t dcid_len;

    if (packet == NULL || new_dcid == NULL) {
        return -1;
    }
    if (packet_len < 6U || new_dcid_len == 0U || new_dcid_len > QUIC_CID_MAX_LEN) {
        return -2;
    }

    first = packet[0];
    if ((first & 0x80U) == 0U) {
        /* Not a long-header packet; cannot contain Initial DCID in expected layout. */
        return -3;
    }

    dcid_len = packet[5];
    if (dcid_len == 0U || dcid_len > QUIC_CID_MAX_LEN) {
        return -4;
    }

    if (new_dcid_len != (size_t)dcid_len) {
        /*
         * In-place update only. Length mismatch would shift subsequent fields and
         * invalidate protected payload framing.
         */
        return -5;
    }

    if (packet_len < (size_t)(6U + dcid_len)) {
        return -6;
    }

    memcpy(packet + 6U, new_dcid, new_dcid_len);
    return 0;
}
