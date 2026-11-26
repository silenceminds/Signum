#ifndef SIGNUM_SMPV2_H
#define SIGNUM_SMPV2_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <openssl/ssl.h>

#define SMPV2_MAGIC_0 0x53
#define SMPV2_MAGIC_1 0x47
#define SMPV2_VERSION 0x02
#define SMPV2_HEADER_LEN 32
#define SMPV2_TAG_LEN 16
#define SMPV2_PAD_BOUNDARY 256
#define SMPV2_MAX_PAYLOAD 65535

typedef enum {
    SMP_OP_CHALLENGE     = 0x01,
    SMP_OP_AUTH_PROOF    = 0x02,
    SMP_OP_SESSION_GRANT = 0x03,
    SMP_OP_OPEN_STREAM   = 0x04,
    SMP_OP_DATA          = 0x05,
    SMP_OP_WINDOW_UPDATE = 0x06,
    SMP_OP_KEY_ROTATE    = 0x07,
    SMP_OP_PING_PONG     = 0x08,
    SMP_OP_CLOSE_STREAM  = 0x09,
    SMP_OP_KILL_SWITCH   = 0x0A
} smp_opcode_t;

typedef struct {
    uint8_t key[32];
    uint8_t direction; /* 0x01 = edge->agent, 0x02 = agent->edge */
    uint64_t next_seq;
    uint64_t bytes_processed;
} smp_cipher_t;

typedef struct {
    smp_opcode_t opcode;
    uint32_t stream_id;
    uint64_t sequence;
    uint16_t actual_len;
    uint8_t *payload;
} smp_frame_t;

void smp_cipher_init(smp_cipher_t *c, const uint8_t key[32], uint8_t direction);
void smp_cipher_ratchet(smp_cipher_t *c, uint64_t seq);
void smp_cipher_zeroize(smp_cipher_t *c);

int smp_write_frame(SSL *ssl, smp_cipher_t *c, smp_opcode_t op,
                    uint32_t stream_id, const uint8_t *plaintext, size_t len);
int smp_read_frame(SSL *ssl, smp_cipher_t *c, smp_frame_t *out_frame,
                   uint8_t *scratch_buf, size_t scratch_cap);

int smp_hmac_sha3_256(const uint8_t *key, size_t key_len,
                      const uint8_t *data, size_t data_len,
                      uint8_t out_mac[32]);

/* TLS 1.3 mTLS + SPKI pinning + X25519MLKEM768 client */
typedef struct {
    SSL_CTX *ctx;
    SSL *ssl;
    int sock_fd;
} signum_tls_t;

int signum_tls_connect(signum_tls_t *t, const char *host, uint16_t port,
                       const char *ca_path, const char *cert_path,
                       const char *key_path, const char *pinned_spki_hex,
                       uint8_t out_init_key[32]);
void signum_tls_close(signum_tls_t *t);

/* Locked-RAM 50-entry HTTP inspection ring buffer */
#define RING_CAP 50
#define RING_MAX_REQ 8192

typedef struct {
    uint64_t id;
    uint16_t target_port;
    size_t len;
    uint8_t data[RING_MAX_REQ];
} ring_entry_t;

typedef struct {
    ring_entry_t *entries;
    size_t head;
    size_t count;
    uint64_t next_id;
} signum_ring_t;

int ring_init(signum_ring_t *r);
void ring_destroy(signum_ring_t *r);
void ring_push(signum_ring_t *r, uint16_t port, const uint8_t *data, size_t len);
int ring_get_by_id(const signum_ring_t *r, uint64_t id, ring_entry_t *out);

#endif
