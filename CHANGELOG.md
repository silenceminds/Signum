# Changelog

All notable changes to **Signum** are documented in this file.

## [0.1.0] - 2026-11-26

### Added
- **`signum-edge` (Rust)**: Async `tokio` + `rustls` TLS 1.3 edge proxy (`:80`, `:443`, `:4443`, raw TCP), mTLS client cert CN/SAN binding, weighted traffic splitting, static fallback responses, bounded channel backpressure, non-blocking `TelemetrySink`, and 64-byte sliding-window outbound secret scanner.
- **`SMPv2` Wire Protocol**: 32-byte big-endian header, ChaCha20-Poly1305 inner AEAD with 64-bit monotonic sequence AAD, 256-byte bucket padding, 15m/1GB key rotation, and `0x01..0x0A` opcodes.
- **`signum-agent` & `signum-ctl` (C11)**: Cross-platform (`ws2_32`/POSIX + OpenSSL 3.x) local agent with SHA-256 SPKI pinning, `X25519MLKEM768`, `VirtualLock`/`mlock` RAM locking, `SecureZeroMemory`/`explicit_bzero`, hardcoded `127.0.0.1` pinning, Windows Job Object / Linux `prctl` sandbox, 50-entry locked-RAM request ring buffer, and `signum-ctl` (`status`, `replay`, `kill`) with `WaitNamedPipeA` contention retries.
- **Layer 21 & Firewalls**: `default_deny_unauthenticated` mode, `--gen-key-512`, `X-Signum-Key-512` constant-time verification, `X-Signum-Auth-512` HMAC-SHA512 request signing, plus `scripts/firewall-linux.sh` and `scripts/firewall-windows.ps1`.
- **Tests & Docs**: 4 Rust unit tests, `scripts/e2e_test.py`, `scripts/stress_400_test.py` (399 vectors + 399-vector simultaneous storm), and Apache 2.0 license.
