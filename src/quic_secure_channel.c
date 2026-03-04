#include "quic_secure_channel.h"

#include <arpa/inet.h>
#include <errno.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define QSC_NONCE_LEN 12U
#define QSC_TAG_LEN 16U
#define QSC_SCID_LEN 8U
#define QSC_MIN_DGRAM_LEN 80U
#define QSC_MAX_DGRAM_LEN 1500U
#define QSC_PLAIN_HDR_LEN 8U
#define QSC_CID_MAGIC 0xA7U

static const uint8_t qsc_default_psk[32] = {
    0x8A, 0x31, 0x51, 0xDE, 0x42, 0xF9, 0xC8, 0x7A,
    0xD4, 0x16, 0x9C, 0x2E, 0xB4, 0x23, 0x19, 0x54,
    0x60, 0x3B, 0x77, 0xAA, 0xC5, 0x0D, 0xE1, 0x98,
    0xF0, 0x83, 0x62, 0x34, 0x17, 0x9A, 0x4E, 0xBD
};

static int qsc_hex_value(char c)
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

static int qsc_parse_psk_hex(const char *hex, uint8_t out[32])
{
    size_t i;

    if (hex == NULL) {
        return -1;
    }
    if (strlen(hex) != 64U) {
        return -2;
    }

    for (i = 0; i < 32U; ++i) {
        int hi = qsc_hex_value(hex[2U * i]);
        int lo = qsc_hex_value(hex[2U * i + 1U]);
        if (hi < 0 || lo < 0) {
            return -3;
        }
        out[i] = (uint8_t)((hi << 4) | lo);
    }

    return 0;
}

static size_t qsc_varint_len(uint64_t v)
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

static int qsc_varint_encode(uint64_t v, uint8_t *out, size_t out_cap, size_t *written)
{
    size_t n = qsc_varint_len(v);

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

static int qsc_varint_decode(const uint8_t *in,
                             size_t in_len,
                             uint64_t *value,
                             size_t *consumed)
{
    size_t n;

    if (in == NULL || value == NULL || consumed == NULL || in_len == 0U) {
        return -1;
    }

    n = (size_t)(1U << ((in[0] >> 6) & 0x03U));
    if (n > in_len) {
        return -2;
    }

    if (n == 1) {
        *value = (uint64_t)(in[0] & 0x3FU);
    } else if (n == 2) {
        *value = ((uint64_t)(in[0] & 0x3FU) << 8) |
                 (uint64_t)in[1];
    } else if (n == 4) {
        *value = ((uint64_t)(in[0] & 0x3FU) << 24) |
                 ((uint64_t)in[1] << 16) |
                 ((uint64_t)in[2] << 8) |
                 (uint64_t)in[3];
    } else {
        *value = ((uint64_t)(in[0] & 0x3FU) << 56) |
                 ((uint64_t)in[1] << 48) |
                 ((uint64_t)in[2] << 40) |
                 ((uint64_t)in[3] << 32) |
                 ((uint64_t)in[4] << 24) |
                 ((uint64_t)in[5] << 16) |
                 ((uint64_t)in[6] << 8) |
                 (uint64_t)in[7];
    }

    *consumed = n;
    return 0;
}

static int qsc_encrypt_gcm(const uint8_t key[32],
                           const uint8_t nonce[QSC_NONCE_LEN],
                           const uint8_t *aad,
                           size_t aad_len,
                           const uint8_t *plain,
                           size_t plain_len,
                           uint8_t *cipher,
                           uint8_t tag[QSC_TAG_LEN])
{
    EVP_CIPHER_CTX *ctx;
    int out_len = 0;
    int tmp_len = 0;

    if (key == NULL || nonce == NULL || plain == NULL || cipher == NULL || tag == NULL) {
        return -1;
    }

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        return -2;
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, QSC_NONCE_LEN, NULL) != 1 ||
        EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -3;
    }

    if (aad != NULL && aad_len > 0U) {
        if (EVP_EncryptUpdate(ctx, NULL, &tmp_len, aad, (int)aad_len) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return -4;
        }
    }

    if (EVP_EncryptUpdate(ctx, cipher, &out_len, plain, (int)plain_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -5;
    }

    if (EVP_EncryptFinal_ex(ctx, cipher + out_len, &tmp_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -6;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, QSC_TAG_LEN, tag) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -7;
    }

    EVP_CIPHER_CTX_free(ctx);
    return out_len + tmp_len;
}

static int qsc_decrypt_gcm(const uint8_t key[32],
                           const uint8_t nonce[QSC_NONCE_LEN],
                           const uint8_t *aad,
                           size_t aad_len,
                           const uint8_t *cipher,
                           size_t cipher_len,
                           const uint8_t tag[QSC_TAG_LEN],
                           uint8_t *plain)
{
    EVP_CIPHER_CTX *ctx;
    int out_len = 0;
    int tmp_len = 0;

    if (key == NULL || nonce == NULL || cipher == NULL || tag == NULL || plain == NULL) {
        return -1;
    }

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        return -2;
    }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, QSC_NONCE_LEN, NULL) != 1 ||
        EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -3;
    }

    if (aad != NULL && aad_len > 0U) {
        if (EVP_DecryptUpdate(ctx, NULL, &tmp_len, aad, (int)aad_len) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return -4;
        }
    }

    if (EVP_DecryptUpdate(ctx, plain, &out_len, cipher, (int)cipher_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -5;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, QSC_TAG_LEN, (void *)tag) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -6;
    }

    if (EVP_DecryptFinal_ex(ctx, plain + out_len, &tmp_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -7;
    }

    EVP_CIPHER_CTX_free(ctx);
    return out_len + tmp_len;
}

static uint8_t qsc_first_byte_for_type(uint8_t msg_type)
{
    if (msg_type == QSC_MSG_HELLO || msg_type == QSC_MSG_HELLO_ACK) {
        return 0xC1U; /* Initial */
    }
    return 0xE1U; /* Handshake-like long header */
}

void qsc_sleep_ms(uint32_t ms)
{
    struct timespec req;

    req.tv_sec = (time_t)(ms / 1000U);
    req.tv_nsec = (long)((ms % 1000U) * 1000000UL);

    while (nanosleep(&req, &req) == -1 && errno == EINTR) {
        /* Continue sleeping for remaining interval. */
    }
}

int qsc_context_init(qsc_context_t *ctx, const qsc_config_t *cfg)
{
    uint8_t rnd[4] = {0};

    if (ctx == NULL || cfg == NULL) {
        return -1;
    }

    memset(ctx, 0, sizeof(*ctx));

    ctx->cid_len = (cfg->cid_len == 0U) ? 16U : cfg->cid_len;
    if (ctx->cid_len > QUIC_CID_MAX_LEN) {
        ctx->cid_len = QUIC_CID_MAX_LEN;
    }

    if (cfg->psk_hex != NULL) {
        if (qsc_parse_psk_hex(cfg->psk_hex, ctx->psk) != 0) {
            return -2;
        }
    } else {
        memcpy(ctx->psk, qsc_default_psk, sizeof(ctx->psk));
    }

    if (quic_cid_injector_init(&ctx->injector) != 0) {
        return -3;
    }
    ctx->injector_initialized = 1;

    if (RAND_bytes(rnd, (int)sizeof(rnd)) != 1 &&
        quic_entropy_fill(&ctx->injector, rnd, sizeof(rnd)) != 0) {
        memset(rnd, 0, sizeof(rnd));
    }
    ctx->tx_packet_number = ((uint32_t)rnd[0] << 24) |
                            ((uint32_t)rnd[1] << 16) |
                            ((uint32_t)rnd[2] << 8) |
                            (uint32_t)rnd[3];

    if (cfg->iface != NULL && cfg->iface[0] != '\0') {
        uint32_t max_iat = (cfg->max_iat_ms == 0U) ? 5000U : cfg->max_iat_ms;
        uint32_t rebuild = (cfg->alias_rebuild_interval == 0U)
                               ? 256U
                               : cfg->alias_rebuild_interval;
        if (tp_engine_init(&ctx->profile, max_iat, rebuild) == 0) {
            ctx->profile_initialized = 1;
            if (tp_engine_start_capture(&ctx->profile,
                                        cfg->iface,
                                        cfg->profile_bpf,
                                        2048,
                                        1,
                                        100) == 0) {
                ctx->profile_enabled = 1;
            } else {
                fprintf(stderr,
                        "[qsc] warning: failed to start profile capture on %s; fallback to defaults\n",
                        cfg->iface);
            }
        } else {
            fprintf(stderr,
                    "[qsc] warning: failed to init profile engine; fallback to defaults\n");
        }
    }

    return 0;
}

void qsc_context_destroy(qsc_context_t *ctx)
{
    if (ctx == NULL) {
        return;
    }

    if (ctx->profile_initialized) {
        tp_engine_destroy(&ctx->profile);
        ctx->profile_initialized = 0;
        ctx->profile_enabled = 0;
    }

    if (ctx->injector_initialized) {
        quic_cid_injector_destroy(&ctx->injector);
        ctx->injector_initialized = 0;
    }
}

const char *qsc_context_init_error(int rc)
{
    switch (rc) {
    case 0:
        return "ok";
    case -1:
        return "invalid argument";
    case -2:
        return "invalid PSK format (must be 64 hex characters)";
    case -3:
        return "failed to initialize CID injector";
    default:
        return "unknown error";
    }
}

int qsc_set_entropy(qsc_context_t *ctx, const uint8_t *entropy, size_t entropy_len)
{
    if (ctx == NULL || !ctx->injector_initialized) {
        return -1;
    }
    return quic_cid_set_entropy(&ctx->injector, entropy, entropy_len);
}

static void qsc_sample_shape(qsc_context_t *ctx, uint16_t *len, uint32_t *delay_ms)
{
    if (ctx != NULL && ctx->profile_enabled &&
        tp_engine_sample(&ctx->profile, len, delay_ms) == 0) {
        if (*len < QSC_MIN_DGRAM_LEN) {
            *len = QSC_MIN_DGRAM_LEN;
        }
        if (*len > QSC_MAX_DGRAM_LEN) {
            *len = QSC_MAX_DGRAM_LEN;
        }
        return;
    }

    *len = 1200U;
    *delay_ms = 10U;
}

int qsc_prepare_packet(qsc_context_t *ctx,
                       uint8_t msg_type,
                       uint32_t seq,
                       const uint8_t *text,
                       uint16_t text_len,
                       uint8_t *out_packet,
                       size_t out_cap,
                       size_t *out_len,
                       uint16_t *applied_target_len,
                       uint32_t *next_delay_ms)
{
    uint8_t dcid[QUIC_CID_MAX_LEN];
    uint8_t scid[QSC_SCID_LEN];
    uint8_t plain[QSC_MAX_DGRAM_LEN];
    uint8_t nonce[QSC_NONCE_LEN];
    uint8_t tag[QSC_TAG_LEN];
    uint16_t sampled_len = 0;
    uint32_t sampled_delay = 0;
    uint8_t first_byte;
    uint16_t target_len;
    size_t plain_base_len;
    size_t base_without_len;
    size_t chosen_target = 0;
    size_t chosen_len_field = 0;
    uint64_t chosen_quic_len = 0;
    size_t chosen_encrypted_len = 0;
    size_t plain_len;
    size_t off;
    size_t aad_len;
    size_t t;
    int enc_len;

    if (ctx == NULL || out_packet == NULL || out_len == NULL) {
        return -1;
    }
    if (text_len > 0U && text == NULL) {
        return -2;
    }
    if (text_len > QSC_MAX_TEXT_LEN) {
        return -3;
    }

    qsc_sample_shape(ctx, &sampled_len, &sampled_delay);
    first_byte = qsc_first_byte_for_type(msg_type);

    target_len = sampled_len;
    if (target_len < QSC_MIN_DGRAM_LEN) {
        target_len = QSC_MIN_DGRAM_LEN;
    }
    if (first_byte == 0xC1U && target_len < 1200U) {
        target_len = 1200U;
    }

    plain_base_len = QSC_PLAIN_HDR_LEN + text_len;
    base_without_len = 1U + 4U + 1U + ctx->cid_len + 1U + QSC_SCID_LEN + 1U;

    for (t = target_len; t <= QSC_MAX_DGRAM_LEN; ++t) {
        size_t i;
        for (i = 0; i < 3U; ++i) {
            size_t len_field = (i == 0U) ? 1U : (i == 1U ? 2U : 4U);
            uint64_t quic_len;
            size_t encrypted_len;
            if (t <= base_without_len + len_field + 2U) {
                continue;
            }
            quic_len = (uint64_t)t - (uint64_t)base_without_len - (uint64_t)len_field;
            if (qsc_varint_len(quic_len) != len_field || quic_len < 2U) {
                continue;
            }
            encrypted_len = (size_t)(quic_len - 2U);
            if (encrypted_len < QSC_NONCE_LEN + QSC_TAG_LEN + plain_base_len) {
                continue;
            }
            chosen_target = t;
            chosen_len_field = len_field;
            chosen_quic_len = quic_len;
            chosen_encrypted_len = encrypted_len;
            break;
        }
        if (chosen_target != 0U) {
            break;
        }
    }

    if (chosen_target == 0U || chosen_target > out_cap) {
        return -4;
    }

    plain_len = chosen_encrypted_len - QSC_NONCE_LEN - QSC_TAG_LEN;
    if (plain_len < plain_base_len || plain_len > sizeof(plain)) {
        return -5;
    }

    memset(plain, 0, plain_len);
    plain[0] = msg_type;
    plain[1] = 0;
    plain[2] = (uint8_t)((seq >> 24) & 0xFFU);
    plain[3] = (uint8_t)((seq >> 16) & 0xFFU);
    plain[4] = (uint8_t)((seq >> 8) & 0xFFU);
    plain[5] = (uint8_t)(seq & 0xFFU);
    plain[6] = (uint8_t)((text_len >> 8) & 0xFFU);
    plain[7] = (uint8_t)(text_len & 0xFFU);
    if (text_len > 0U) {
        memcpy(plain + QSC_PLAIN_HDR_LEN, text, text_len);
    }
    if (plain_len > plain_base_len) {
        if (quic_entropy_fill(&ctx->injector,
                              plain + plain_base_len,
                              plain_len - plain_base_len) != 0) {
            return -6;
        }
    }

    if (quic_cid_generate(&ctx->injector, dcid, ctx->cid_len) != 0 ||
        quic_entropy_fill(&ctx->injector, scid, sizeof(scid)) != 0) {
        return -7;
    }
    if (RAND_bytes(nonce, (int)sizeof(nonce)) != 1 &&
        quic_entropy_fill(&ctx->injector, nonce, sizeof(nonce)) != 0) {
        return -7;
    }

    if (ctx->cid_len >= 6U) {
        dcid[0] = QSC_CID_MAGIC;
        dcid[1] = msg_type;
        dcid[2] = (uint8_t)((seq >> 24) & 0xFFU);
        dcid[3] = (uint8_t)((seq >> 16) & 0xFFU);
        dcid[4] = (uint8_t)((seq >> 8) & 0xFFU);
        dcid[5] = (uint8_t)(seq & 0xFFU);
    }

    off = 0;
    out_packet[off++] = first_byte;
    out_packet[off++] = 0x00U;
    out_packet[off++] = 0x00U;
    out_packet[off++] = 0x00U;
    out_packet[off++] = 0x01U;

    out_packet[off++] = (uint8_t)ctx->cid_len;
    memcpy(out_packet + off, dcid, ctx->cid_len);
    off += ctx->cid_len;

    out_packet[off++] = (uint8_t)sizeof(scid);
    memcpy(out_packet + off, scid, sizeof(scid));
    off += sizeof(scid);

    out_packet[off++] = 0x00U;

    {
        size_t written = 0;
        if (qsc_varint_encode(chosen_quic_len,
                              out_packet + off,
                              out_cap - off,
                              &written) != 0 ||
            written != chosen_len_field) {
            return -8;
        }
        off += written;
    }

    out_packet[off++] = (uint8_t)((ctx->tx_packet_number >> 8) & 0xFFU);
    out_packet[off++] = (uint8_t)(ctx->tx_packet_number & 0xFFU);
    ctx->tx_packet_number++;
    aad_len = off;

    memcpy(out_packet + off, nonce, sizeof(nonce));
    off += sizeof(nonce);

    enc_len = qsc_encrypt_gcm(ctx->psk,
                              nonce,
                              out_packet,
                              aad_len,
                              plain,
                              plain_len,
                              out_packet + off,
                              tag);
    if (enc_len < 0 || (size_t)enc_len != plain_len) {
        return -9;
    }
    off += (size_t)enc_len;

    memcpy(out_packet + off, tag, sizeof(tag));
    off += sizeof(tag);

    if (off != chosen_target) {
        return -10;
    }

    *out_len = off;
    if (applied_target_len != NULL) {
        *applied_target_len = (uint16_t)chosen_target;
    }
    if (next_delay_ms != NULL) {
        *next_delay_ms = sampled_delay;
    }

    return 0;
}

int qsc_parse_packet(qsc_context_t *ctx,
                     const uint8_t *packet,
                     size_t packet_len,
                     qsc_message_t *msg_out)
{
    uint8_t first;
    uint8_t dcid_len;
    uint8_t scid_len;
    const uint8_t *dcid;
    uint64_t token_len;
    uint64_t quic_len;
    size_t consumed;
    size_t pn_len;
    size_t off;
    size_t aad_len;
    const uint8_t *nonce;
    const uint8_t *cipher;
    size_t cipher_len;
    const uint8_t *tag;
    uint8_t plain[QSC_MAX_DGRAM_LEN];
    int plain_len;
    uint16_t text_len;

    if (ctx == NULL || packet == NULL || msg_out == NULL) {
        return -1;
    }
    if (packet_len < 7U) {
        return -2;
    }

    memset(msg_out, 0, sizeof(*msg_out));

    off = 0;
    first = packet[off++];
    if ((first & 0x80U) == 0U || (first & 0x40U) == 0U) {
        return -3;
    }

    /* version */
    if (packet_len < off + 4U) {
        return -4;
    }
    off += 4U;

    dcid_len = packet[off++];
    if (dcid_len == 0U || dcid_len > QUIC_CID_MAX_LEN || packet_len < off + dcid_len + 1U) {
        return -5;
    }
    dcid = packet + off;
    off += dcid_len;

    scid_len = packet[off++];
    if (scid_len > QUIC_CID_MAX_LEN || packet_len < off + scid_len + 1U) {
        return -6;
    }
    off += scid_len;

    if (qsc_varint_decode(packet + off, packet_len - off, &token_len, &consumed) != 0) {
        return -7;
    }
    off += consumed;
    if (packet_len < off + (size_t)token_len) {
        return -8;
    }
    off += (size_t)token_len;

    if (qsc_varint_decode(packet + off, packet_len - off, &quic_len, &consumed) != 0) {
        return -9;
    }
    off += consumed;

    pn_len = (size_t)((first & 0x03U) + 1U);
    if (quic_len < pn_len || packet_len < off + (size_t)quic_len) {
        return -10;
    }

    off += pn_len;
    aad_len = off;

    if ((size_t)quic_len < pn_len + QSC_NONCE_LEN + QSC_TAG_LEN) {
        return -11;
    }

    nonce = packet + off;
    off += QSC_NONCE_LEN;

    cipher_len = (size_t)quic_len - pn_len - QSC_NONCE_LEN - QSC_TAG_LEN;
    cipher = packet + off;
    off += cipher_len;

    tag = packet + off;

    if (cipher_len > sizeof(plain)) {
        return -12;
    }

    plain_len = qsc_decrypt_gcm(ctx->psk,
                                nonce,
                                packet,
                                aad_len,
                                cipher,
                                cipher_len,
                                tag,
                                plain);
    if (plain_len < (int)QSC_PLAIN_HDR_LEN) {
        return -13;
    }

    msg_out->msg_type = plain[0];
    msg_out->seq = ((uint32_t)plain[2] << 24) |
                   ((uint32_t)plain[3] << 16) |
                   ((uint32_t)plain[4] << 8) |
                   (uint32_t)plain[5];

    text_len = (uint16_t)(((uint16_t)plain[6] << 8) | (uint16_t)plain[7]);
    if (text_len > QSC_MAX_TEXT_LEN ||
        (size_t)plain_len < QSC_PLAIN_HDR_LEN + text_len) {
        return -14;
    }

    msg_out->text_len = text_len;
    if (text_len > 0U) {
        memcpy(msg_out->text, plain + QSC_PLAIN_HDR_LEN, text_len);
    }

    if (dcid_len >= 2U && dcid[0] == QSC_CID_MAGIC) {
        msg_out->cid_meta_valid = 1;
        msg_out->cid_msg_type = dcid[1];
        if (dcid_len >= 6U) {
            msg_out->cid_seq = ((uint32_t)dcid[2] << 24) |
                               ((uint32_t)dcid[3] << 16) |
                               ((uint32_t)dcid[4] << 8) |
                               (uint32_t)dcid[5];
        }
    }

    return 0;
}

const char *qsc_msg_type_name(uint8_t msg_type)
{
    switch (msg_type) {
    case QSC_MSG_HELLO:
        return "HELLO";
    case QSC_MSG_HELLO_ACK:
        return "HELLO_ACK";
    case QSC_MSG_DATA:
        return "DATA";
    case QSC_MSG_DATA_ACK:
        return "DATA_ACK";
    case QSC_MSG_BYE:
        return "BYE";
    case QSC_MSG_BYE_ACK:
        return "BYE_ACK";
    default:
        return "UNKNOWN";
    }
}
