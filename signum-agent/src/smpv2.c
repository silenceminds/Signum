#include "smpv2.h"
#include "platform.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/core_names.h>
#include <string.h>

static void put_be16(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)(v & 0xFF);
}

static void put_be32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)(v & 0xFF);
}

static void put_be64(uint8_t *p, uint64_t v) {
    for (int i = 0; i < 8; i++) {
        p[i] = (uint8_t)((v >> (56 - i * 8)) & 0xFF);
    }
}

static uint16_t get_be16(const uint8_t *p) {
    return ((uint16_t)p[0] << 8) | (uint16_t)p[1];
}

static uint32_t get_be32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8)  | (uint32_t)p[3];
}

static uint64_t get_be64(const uint8_t *p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) {
        v = (v << 8) | (uint64_t)p[i];
    }
    return v;
}

static void make_nonce(uint8_t dir, uint64_t seq, uint8_t nonce[12]) {
    memset(nonce, 0, 12);
    nonce[0] = dir;
    put_be64(nonce + 4, seq);
}

static int ssl_write_all(SSL *ssl, const uint8_t *buf, size_t len) {
    size_t sent = 0;
    while (sent < len) {
        int n = SSL_write(ssl, buf + sent, (int)(len - sent));
        if (n <= 0) return -1;
        sent += (size_t)n;
    }
    return 0;
}

static int ssl_read_all(SSL *ssl, uint8_t *buf, size_t len) {
    size_t got = 0;
    while (got < len) {
        int n = SSL_read(ssl, buf + got, (int)(len - got));
        if (n <= 0) return -1;
        got += (size_t)n;
    }
    return 0;
}

void smp_cipher_init(smp_cipher_t *c, const uint8_t key[32], uint8_t direction) {
    memcpy(c->key, key, 32);
    c->direction = direction;
    c->next_seq = 1;
    c->bytes_processed = 0;
}

void smp_cipher_ratchet(smp_cipher_t *c, uint64_t seq) {
    uint8_t new_key[32];
    uint8_t seq_be[8];
    put_be64(seq_be, seq);

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (ctx) {
        unsigned int out_len = 0;
        if (EVP_DigestInit_ex(ctx, EVP_sha3_256(), NULL) == 1 &&
            EVP_DigestUpdate(ctx, c->key, 32) == 1 &&
            EVP_DigestUpdate(ctx, "signum-ratchet", 14) == 1 &&
            EVP_DigestUpdate(ctx, seq_be, 8) == 1 &&
            EVP_DigestFinal_ex(ctx, new_key, &out_len) == 1 &&
            out_len == 32) {
            memcpy(c->key, new_key, 32);
        }
        EVP_MD_CTX_free(ctx);
    }
    sig_secure_zero(new_key, sizeof(new_key));
    c->bytes_processed = 0;
}

void smp_cipher_zeroize(smp_cipher_t *c) {
    sig_secure_zero(c->key, sizeof(c->key));
}

int smp_hmac_sha3_256(const uint8_t *key, size_t key_len,
                      const uint8_t *data, size_t data_len,
                      uint8_t out_mac[32]) {
    EVP_MAC *mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
    if (!mac) return -1;

    EVP_MAC_CTX *ctx = EVP_MAC_CTX_new(mac);
    EVP_MAC_free(mac);
    if (!ctx) return -1;

    OSSL_PARAM params[2];
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, "SHA3-256", 0);
    params[1] = OSSL_PARAM_construct_end();

    size_t out_len = 0;
    int ok = EVP_MAC_init(ctx, key, key_len, params) == 1 &&
             EVP_MAC_update(ctx, data, data_len) == 1 &&
             EVP_MAC_final(ctx, out_mac, &out_len, 32) == 1 &&
             out_len == 32;

    EVP_MAC_CTX_free(ctx);
    return ok ? 0 : -1;
}

int smp_write_frame(SSL *ssl, smp_cipher_t *c, smp_opcode_t op,
                    uint32_t stream_id, const uint8_t *plaintext, size_t len) {
    if (len > SMPV2_MAX_PAYLOAD) return -1;

    uint16_t actual_len = (uint16_t)len;
    size_t padded_len = 0;
    if (actual_len > 0) {
        padded_len = ((actual_len + SMPV2_PAD_BOUNDARY - 1) / SMPV2_PAD_BOUNDARY) * SMPV2_PAD_BOUNDARY;
        if (padded_len > SMPV2_MAX_PAYLOAD) padded_len = SMPV2_MAX_PAYLOAD;
    }

    size_t total_len = SMPV2_HEADER_LEN + padded_len + SMPV2_TAG_LEN;
    uint8_t *wire = (uint8_t *)sig_alloc_locked(total_len);
    if (!wire) return -1;

    uint64_t seq = c->next_seq++;
    wire[0] = SMPV2_MAGIC_0;
    wire[1] = SMPV2_MAGIC_1;
    wire[2] = SMPV2_VERSION;
    wire[3] = (uint8_t)op;
    put_be32(wire + 4, stream_id);
    put_be64(wire + 8, seq);
    put_be16(wire + 16, actual_len);
    put_be16(wire + 18, (uint16_t)padded_len);

    uint8_t *pt_buf = NULL;
    if (padded_len > 0) {
        pt_buf = (uint8_t *)sig_alloc_locked(padded_len);
        if (!pt_buf) {
            sig_free_locked(wire, total_len);
            return -1;
        }
        memcpy(pt_buf, plaintext, actual_len);
        if (padded_len > actual_len) {
            RAND_bytes(pt_buf + actual_len, (int)(padded_len - actual_len));
        }
    }

    uint8_t nonce[12];
    make_nonce(c->direction, seq, nonce);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int ok = 0;
    int outl = 0;
    uint8_t tag[16];

    if (ctx &&
        EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, c->key, nonce) == 1 &&
        EVP_EncryptUpdate(ctx, NULL, &outl, wire, 20) == 1 &&
        (padded_len == 0 || EVP_EncryptUpdate(ctx, wire + SMPV2_HEADER_LEN, &outl, pt_buf, (int)padded_len) == 1) &&
        EVP_EncryptFinal_ex(ctx, wire + SMPV2_HEADER_LEN + outl, &outl) == 1 &&
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag) == 1) {
        memcpy(wire + 20, tag, 12);
        memcpy(wire + SMPV2_HEADER_LEN + padded_len, tag, SMPV2_TAG_LEN);
        ok = 1;
    }

    if (ctx) EVP_CIPHER_CTX_free(ctx);
    if (pt_buf) sig_free_locked(pt_buf, padded_len);

    int rc = -1;
    if (ok) {
        rc = ssl_write_all(ssl, wire, total_len);
        c->bytes_processed += total_len;
    }
    sig_free_locked(wire, total_len);
    return rc;
}

int smp_read_frame(SSL *ssl, smp_cipher_t *c, smp_frame_t *out_frame,
                   uint8_t *scratch_buf, size_t scratch_cap) {
    uint8_t header[SMPV2_HEADER_LEN];
    if (ssl_read_all(ssl, header, SMPV2_HEADER_LEN) != 0) return -1;

    if (header[0] != SMPV2_MAGIC_0 || header[1] != SMPV2_MAGIC_1 || header[2] != SMPV2_VERSION) {
        return -1;
    }

    uint8_t op = header[3];
    uint32_t stream_id = get_be32(header + 4);
    uint64_t seq = get_be64(header + 8);
    uint16_t actual_len = get_be16(header + 16);
    uint16_t padded_len = get_be16(header + 18);

    if (seq != c->next_seq || actual_len > padded_len || padded_len > scratch_cap) {
        return -1;
    }

    size_t body_len = (size_t)padded_len + SMPV2_TAG_LEN;
    uint8_t *ct = (uint8_t *)sig_alloc_locked(body_len);
    if (!ct) return -1;

    if (ssl_read_all(ssl, ct, body_len) != 0) {
        sig_free_locked(ct, body_len);
        return -1;
    }

    uint8_t *tag = ct + padded_len;
    if (memcmp(header + 20, tag, 12) != 0) {
        sig_free_locked(ct, body_len);
        return -1;
    }

    uint8_t nonce[12];
    make_nonce(c->direction, seq, nonce);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int ok = 0;
    int outl = 0;

    if (ctx &&
        EVP_DecryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, c->key, nonce) == 1 &&
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, tag) == 1 &&
        EVP_DecryptUpdate(ctx, NULL, &outl, header, 20) == 1 &&
        (padded_len == 0 || EVP_DecryptUpdate(ctx, scratch_buf, &outl, ct, (int)padded_len) == 1) &&
        EVP_DecryptFinal_ex(ctx, scratch_buf + outl, &outl) == 1) {
        ok = 1;
    }

    if (ctx) EVP_CIPHER_CTX_free(ctx);
    sig_free_locked(ct, body_len);

    if (!ok) return -1;

    c->next_seq++;
    c->bytes_processed += SMPV2_HEADER_LEN + body_len;

    out_frame->opcode = (smp_opcode_t)op;
    out_frame->stream_id = stream_id;
    out_frame->sequence = seq;
    out_frame->actual_len = actual_len;
    out_frame->payload = scratch_buf;
    return 0;
}
