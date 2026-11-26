# 21-Layer Security Reference

1. **TLS 1.3 Only** (`TLS_AES_256_GCM_SHA384` / `TLS_CHACHA20_POLY1305_SHA256`)
2. **Mutual TLS (mTLS)** client X.509 verification on `:4443`
3. **SHA-256 SPKI Public Key Pinning** in `signum-agent`
4. **Hybrid PQ Key Exchange** (`X25519MLKEM768` with classical fallback)
5. **Inner ChaCha20-Poly1305 AEAD** (`SMPv2` frame encryption)
6. **64-Bit Monotonic Sequence Number** bound in AEAD AAD
7. **32-Byte Random Challenge + HMAC-SHA3-256** handshake
8. **256-Byte Bucket Frame Padding** using CSPRNG bytes
9. **15-Minute / 1 GB Ephemeral Key Rotation** (`0x07 KEY_ROTATE`)
10. **Subdomain Bound to Client Cert CN / DNS SAN**
11. **Socket-Level IPv4/IPv6 CIDR Allowlist**
12. **Edge JWT (HS256) & Webhook HMAC (`X-Hub-Signature-256`)**
13. **Strict HTTP/1.1 Smuggling Validator**
14. **64-Byte Sliding-Window Outbound Secret Scanner**
15. **Hardcoded `127.0.0.1` Destination Pinning** in `signum-agent`
16. **Per-IP Token-Bucket Rate Limit & 5s Header Timeout**
17. **Physical RAM Locking** (`VirtualLock` / `mlock`)
18. **Zero-Disk Execution & `SecureZeroMemory` / `explicit_bzero`**
19. **OS Process Sandboxing** (Windows Job Object / Linux `prctl`)
20. **10s Heartbeat Dead-Man's Switch + `0x0A KILL_SWITCH`**
21. **512-Bit Access Key (`X-Signum-Key-512`) & HMAC-SHA512 Request Signing (`X-Signum-Auth-512`)** (sequenced strictly after all pre-tunnel security gates and agent selection)
