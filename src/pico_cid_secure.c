#include "pico_cid_secure.h"

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <string.h>

static const uint8_t g_default_psk[PCS_PSK_LEN] = {
    0x5A, 0x26, 0xDF, 0xE1, 0x47, 0x9D, 0x93, 0x20,
    0xBE, 0x11, 0x34, 0x8C, 0x72, 0xD4, 0x0A, 0x66,
    0xE3, 0x19, 0xBC, 0xF2, 0x88, 0x07, 0xC5, 0xAD,
    0x31, 0x42, 0x9A, 0xF0, 0x6D, 0x15, 0x73, 0xCE
};

static int pcs_hex_value(char c)
{
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return 10 + (c - 'a');
    }
    if (c >= 'A' && c <= 'F') {
        return 10 + (c - 'A');
    }
    return -1;
}

int pcs_parse_psk_hex(const char *hex, uint8_t out_psk[PCS_PSK_LEN])
{
    size_t i;

    if (hex == NULL || out_psk == NULL) {
        return -1;
    }
    if (strlen(hex) != PCS_PSK_LEN * 2U) {
        return -2;
    }

    for (i = 0; i < PCS_PSK_LEN; ++i) {
        int hi = pcs_hex_value(hex[i * 2U]);
        int lo = pcs_hex_value(hex[i * 2U + 1U]);
        if (hi < 0 || lo < 0) {
            return -3;
        }
        out_psk[i] = (uint8_t)((hi << 4) | lo);
    }

    return 0;
}

void pcs_default_psk(uint8_t out_psk[PCS_PSK_LEN])
{
    if (out_psk == NULL) {
        return;
    }
    memcpy(out_psk, g_default_psk, PCS_PSK_LEN);
}

size_t pcs_cid_fragment_capacity(uint8_t cid_len)
{
    if (cid_len < PCS_CID_MIN_LEN || cid_len > PCS_CID_MAX_LEN) {
        return 0U;
    }
    return (size_t)cid_len - PCS_CID_MIN_LEN;
}

/*
 * Lightweight deterministic byte stream keyed by one-byte nonce.
 * Goal is traffic-shape camouflage (remove fixed visible CID markers),
 * not cryptographic secrecy.
 */
static uint8_t pcs_cid_stream_byte(uint8_t nonce, uint8_t pos)
{
    uint32_t x = ((uint32_t)nonce << 24) ^
                 (0x9E3779B9U + ((uint32_t)pos * 0x45D9F3BU));
    x ^= x >> 16;
    x *= 0x7FEB352DU;
    x ^= x >> 15;
    x *= 0x846CA68BU;
    x ^= x >> 16;
    return (uint8_t)x;
}

int pcs_encode_cid_fragment(uint8_t *cid,
                            uint8_t cid_len,
                            const pcs_cid_fragment_t *frag)
{
    size_t cap;
    uint8_t nonce = 0U;
    size_t i;
    uint8_t plain[PCS_CID_MAX_LEN];

    if (cid == NULL || frag == NULL) {
        return -1;
    }
    cap = pcs_cid_fragment_capacity(cid_len);
    if (cap == 0U) {
        return -2;
    }
    if (frag->frag_total == 0U || frag->frag_idx >= frag->frag_total) {
        return -3;
    }
    if ((size_t)frag->data_len > cap) {
        return -4;
    }

    memset(plain, 0, sizeof(plain));
    plain[0] = PCS_CID_MAGIC;
    plain[1] = (uint8_t)((frag->session_id >> 24) & 0xFFU);
    plain[2] = (uint8_t)((frag->session_id >> 16) & 0xFFU);
    plain[3] = (uint8_t)((frag->session_id >> 8) & 0xFFU);
    plain[4] = (uint8_t)(frag->session_id & 0xFFU);
    plain[5] = frag->frag_idx;
    plain[6] = frag->frag_total;
    plain[7] = frag->data_len;

    if (frag->data_len > 0U) {
        memcpy(plain + PCS_CID_MIN_LEN, frag->data, frag->data_len);
    }

    if (RAND_bytes(&nonce, 1) != 1) {
        nonce = (uint8_t)((frag->session_id ^ frag->frag_idx ^ frag->frag_total ^ frag->data_len) & 0xFFU);
    }

    /*
     * Keep CID length/capacity unchanged:
     * - byte0 carries nonce mixed with constant marker, so visible value is no longer fixed.
     * - bytes1..N are XOR-whitened by nonce-derived stream.
     */
    cid[0] = (uint8_t)(nonce ^ PCS_CID_MAGIC);
    for (i = 1U; i < cid_len; ++i) {
        cid[i] = (uint8_t)(plain[i] ^ pcs_cid_stream_byte(nonce, (uint8_t)i));
    }

    return 0;
}

int pcs_decode_cid_fragment(const uint8_t *cid,
                            size_t cid_len,
                            pcs_cid_fragment_t *frag_out)
{
    size_t cap;
    uint8_t nonce;
    uint8_t plain[PCS_CID_MAX_LEN];

    if (cid == NULL || frag_out == NULL) {
        return -1;
    }
    if (cid_len < PCS_CID_MIN_LEN || cid_len > PCS_CID_MAX_LEN) {
        return -2;
    }
    memset(frag_out, 0, sizeof(*frag_out));
    memset(plain, 0, sizeof(plain));

    nonce = (uint8_t)(cid[0] ^ PCS_CID_MAGIC);
    plain[0] = PCS_CID_MAGIC;
    {
        size_t i;
        for (i = 1U; i < cid_len; ++i) {
            plain[i] = (uint8_t)(cid[i] ^ pcs_cid_stream_byte(nonce, (uint8_t)i));
        }
    }

    frag_out->session_id = ((uint32_t)plain[1] << 24) |
                           ((uint32_t)plain[2] << 16) |
                           ((uint32_t)plain[3] << 8) |
                           (uint32_t)plain[4];
    frag_out->frag_idx = plain[5];
    frag_out->frag_total = plain[6];
    frag_out->data_len = plain[7];

    cap = cid_len - PCS_CID_MIN_LEN;
    if (frag_out->frag_total == 0U || frag_out->frag_idx >= frag_out->frag_total) {
        return -4;
    }
    if ((size_t)frag_out->data_len > cap) {
        return -5;
    }

    if (frag_out->data_len > 0U) {
        memcpy(frag_out->data, plain + PCS_CID_MIN_LEN, frag_out->data_len);
    }

    return 0;
}

int pcs_compute_auth_hash(const uint8_t psk[PCS_PSK_LEN],
                          uint8_t msg_type,
                          const uint8_t *cid,
                          size_t cid_len,
                          uint8_t out_hash[PCS_HASH_LEN])
{
    EVP_MD_CTX *md_ctx;
    unsigned int out_len = 0;

    if (psk == NULL || cid == NULL || out_hash == NULL) {
        return -1;
    }
    if (cid_len < PCS_CID_MIN_LEN || cid_len > PCS_CID_MAX_LEN) {
        return -2;
    }

    md_ctx = EVP_MD_CTX_new();
    if (md_ctx == NULL) {
        return -3;
    }

    if (EVP_DigestInit_ex(md_ctx, EVP_sha256(), NULL) != 1 ||
        EVP_DigestUpdate(md_ctx, psk, PCS_PSK_LEN) != 1 ||
        EVP_DigestUpdate(md_ctx, cid, cid_len) != 1 ||
        EVP_DigestUpdate(md_ctx, &msg_type, sizeof(msg_type)) != 1 ||
        EVP_DigestFinal_ex(md_ctx, out_hash, &out_len) != 1) {
        EVP_MD_CTX_free(md_ctx);
        return -4;
    }

    EVP_MD_CTX_free(md_ctx);

    if (out_len != PCS_HASH_LEN) {
        return -5;
    }

    return 0;
}

int pcs_build_auth_payload(uint8_t msg_type,
                           const pcs_cid_fragment_t *frag,
                           uint16_t push_port,
                           const uint8_t hash[PCS_HASH_LEN],
                           uint8_t *out,
                           size_t out_cap,
                           size_t *out_len)
{
    if (frag == NULL || hash == NULL || out == NULL || out_len == NULL) {
        return -1;
    }
    if (out_cap < PCS_AUTH_PAYLOAD_LEN) {
        return -2;
    }

    /*
     * Compact binary payload format (44 bytes total):
     * [ver][msg_type][session_id(4)][frag_idx][frag_total][data_len]
     * [flags][push_port(2)][hash(32)]
     */
    out[0] = PCS_AUTH_VERSION;
    out[1] = msg_type;
    out[2] = (uint8_t)((frag->session_id >> 24) & 0xFFU);
    out[3] = (uint8_t)((frag->session_id >> 16) & 0xFFU);
    out[4] = (uint8_t)((frag->session_id >> 8) & 0xFFU);
    out[5] = (uint8_t)(frag->session_id & 0xFFU);
    out[6] = frag->frag_idx;
    out[7] = frag->frag_total;
    out[8] = frag->data_len;
    out[9] = (push_port > 0U) ? PCS_AUTH_FLAG_HAS_PUSH_PORT : 0U;
    out[10] = (uint8_t)((push_port >> 8) & 0xFFU);
    out[11] = (uint8_t)(push_port & 0xFFU);
    memcpy(out + 12U, hash, PCS_HASH_LEN);

    *out_len = PCS_AUTH_PAYLOAD_LEN;
    return 0;
}

int pcs_parse_auth_payload(const uint8_t *in,
                           size_t in_len,
                           pcs_auth_payload_t *out)
{
    if (in == NULL || out == NULL) {
        return -1;
    }
    if (in_len < PCS_AUTH_PAYLOAD_LEN) {
        return -2;
    }
    /*
     * New binary format (no fixed ASCII magic).
     * Backward-compatible with legacy "QCID" framed 45-byte layout.
     */
    if (in_len >= PCS_AUTH_PAYLOAD_LEN && in[0] == PCS_AUTH_VERSION) {
        out->version = in[0];
        out->msg_type = in[1];
        out->session_id = ((uint32_t)in[2] << 24) |
                          ((uint32_t)in[3] << 16) |
                          ((uint32_t)in[4] << 8) |
                          (uint32_t)in[5];
        out->frag_idx = in[6];
        out->frag_total = in[7];
        out->data_len = in[8];
        out->flags = in[9];
        out->push_port = ((uint16_t)in[10] << 8) | (uint16_t)in[11];
        memcpy(out->hash, in + 12U, PCS_HASH_LEN);
    } else if (in_len >= 45U &&
               in[0] == 'Q' &&
               in[1] == 'C' &&
               in[2] == 'I' &&
               in[3] == 'D' &&
               in[4] == PCS_AUTH_VERSION) {
        out->version = in[4];
        out->msg_type = in[5];
        out->session_id = ((uint32_t)in[6] << 24) |
                          ((uint32_t)in[7] << 16) |
                          ((uint32_t)in[8] << 8) |
                          (uint32_t)in[9];
        out->frag_idx = in[10];
        out->frag_total = in[11];
        out->data_len = in[12];
        out->flags = 0U;
        out->push_port = 0U;
        memcpy(out->hash, in + 13U, PCS_HASH_LEN);
    } else {
        return -3;
    }

    if (out->version != PCS_AUTH_VERSION) {
        return -4;
    }
    if (out->msg_type < PCS_MSG_CLIENT_PROOF || out->msg_type > PCS_MSG_CLIENT_PUSH_ACK) {
        return -6;
    }
    if (out->frag_total == 0U || out->frag_idx >= out->frag_total) {
        return -5;
    }
    if ((out->flags & PCS_AUTH_FLAG_HAS_PUSH_PORT) == 0U) {
        out->push_port = 0U;
    }

    return 0;
}

void pcs_hex_encode(const uint8_t *in, size_t in_len, char *out, size_t out_cap)
{
    static const char hex[] = "0123456789abcdef";
    size_t i;

    if (out == NULL || out_cap == 0U) {
        return;
    }
    if (in == NULL || in_len == 0U) {
        out[0] = '\0';
        return;
    }
    if (out_cap < in_len * 2U + 1U) {
        out[0] = '\0';
        return;
    }

    for (i = 0; i < in_len; ++i) {
        out[2U * i] = hex[(in[i] >> 4) & 0x0FU];
        out[2U * i + 1U] = hex[in[i] & 0x0FU];
    }
    out[in_len * 2U] = '\0';
}
