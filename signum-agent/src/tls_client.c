#include "smpv2.h"
#include "platform.h"
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/err.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>

static int hex_to_bytes(const char *hex, uint8_t *out, size_t max_bytes) {
    size_t len = strlen(hex);
    if (len != max_bytes * 2) return -1;
    for (size_t i = 0; i < max_bytes; i++) {
        unsigned int b = 0;
        if (sscanf(hex + i * 2, "%2x", &b) != 1) return -1;
        out[i] = (uint8_t)b;
    }
    return 0;
}

/* Layer 3: SPKI Public Key Pinning */
static int verify_spki_pin(SSL *ssl, const char *pinned_spki_hex) {
    if (!pinned_spki_hex || pinned_spki_hex[0] == '\0') return 0;

    uint8_t expected[32];
    if (hex_to_bytes(pinned_spki_hex, expected, 32) != 0) {
        fprintf(stderr, "[signum-agent] invalid SPKI pin hex length\n");
        return -1;
    }

    X509 *cert = SSL_get1_peer_certificate(ssl);
    if (!cert) return -1;

    int der_len = i2d_X509_PUBKEY(X509_get_X509_PUBKEY(cert), NULL);
    if (der_len <= 0) {
        X509_free(cert);
        return -1;
    }

    uint8_t *der = (uint8_t *)malloc((size_t)der_len);
    if (!der) {
        X509_free(cert);
        return -1;
    }
    uint8_t *p = der;
    i2d_X509_PUBKEY(X509_get_X509_PUBKEY(cert), &p);
    X509_free(cert);

    uint8_t digest[32];
    unsigned int dlen = 0;
    EVP_Digest(der, (size_t)der_len, digest, &dlen, EVP_sha256(), NULL);
    free(der);

    if (dlen != 32 || CRYPTO_memcmp(digest, expected, 32) != 0) {
        fprintf(stderr, "[signum-agent] SPKI pin verification FAILED! Possible MITM.\n");
        fprintf(stderr, "[signum-agent] actual SPKI: ");
        for (int i = 0; i < 32; i++) fprintf(stderr, "%02x", digest[i]);
        fprintf(stderr, "\n[signum-agent] expect SPKI: %s\n", pinned_spki_hex);
        return -1;
    }
    return 0;
}

int signum_tls_connect(signum_tls_t *t, const char *host, uint16_t port,
                       const char *ca_path, const char *cert_path,
                       const char *key_path, const char *pinned_spki_hex,
                       uint8_t out_init_key[32]) {
    memset(t, 0, sizeof(*t));
    t->sock_fd = -1;

    t->ctx = SSL_CTX_new(TLS_client_method());
    if (!t->ctx) return -1;

    /* Layer 1: TLS 1.3 Only */
    SSL_CTX_set_min_proto_version(t->ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(t->ctx, TLS1_3_VERSION);
    SSL_CTX_set_ciphersuites(t->ctx, "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256");

    /* Layer 4: Hybrid PQ Key Exchange (X25519MLKEM768) with classical fallback */
    if (SSL_CTX_set1_groups_list(t->ctx, "X25519MLKEM768:X25519:P-256") != 1) {
        SSL_CTX_set1_groups_list(t->ctx, "X25519:P-256");
    }

    /* Layer 2: mTLS Client Certificate + CA Verification */
    if (SSL_CTX_load_verify_locations(t->ctx, ca_path, NULL) != 1) {
        fprintf(stderr, "[signum-agent] failed to load CA: %s\n", ca_path);
        signum_tls_close(t);
        return -1;
    }
    SSL_CTX_set_verify(t->ctx, SSL_VERIFY_PEER, NULL);

    if (SSL_CTX_use_certificate_chain_file(t->ctx, cert_path) != 1 ||
        SSL_CTX_use_PrivateKey_file(t->ctx, key_path, SSL_FILETYPE_PEM) != 1 ||
        SSL_CTX_check_private_key(t->ctx) != 1) {
        fprintf(stderr, "[signum-agent] failed to load client mTLS cert/key\n");
        signum_tls_close(t);
        return -1;
    }

    sig_sock_t sock = sig_tcp_connect(host, port, true);
    if (sock == SIG_INVALID_SOCK) {
        signum_tls_close(t);
        return -1;
    }
    t->sock_fd = (int)sock;

    t->ssl = SSL_new(t->ctx);
    if (!t->ssl) {
        signum_tls_close(t);
        return -1;
    }

    struct in_addr ipv4;
    struct in6_addr ipv6;
    if (inet_pton(AF_INET, host, &ipv4) != 1 && inet_pton(AF_INET6, host, &ipv6) != 1) {
        SSL_set_tlsext_host_name(t->ssl, host);
    }
    SSL_set_fd(t->ssl, t->sock_fd);

    if (SSL_connect(t->ssl) != 1) {
        ERR_print_errors_fp(stderr);
        signum_tls_close(t);
        return -1;
    }

    if (verify_spki_pin(t->ssl, pinned_spki_hex) != 0) {
        signum_tls_close(t);
        return -1;
    }

    /* Derive initial SMPv2 symmetric key via TLS 1.3 RFC 8446 Exporter */
    const char label[] = "EXPORTER-signum-smpv2";
    if (SSL_export_keying_material(t->ssl, out_init_key, 32,
                                   label, sizeof(label) - 1,
                                   NULL, 0, 0) != 1) {
        signum_tls_close(t);
        return -1;
    }

    return 0;
}

void signum_tls_close(signum_tls_t *t) {
    if (t->ssl) {
        SSL_shutdown(t->ssl);
        SSL_free(t->ssl);
        t->ssl = NULL;
    }
    if (t->sock_fd != -1) {
        sig_sock_close((sig_sock_t)t->sock_fd);
        t->sock_fd = -1;
    }
    if (t->ctx) {
        SSL_CTX_free(t->ctx);
        t->ctx = NULL;
    }
}
