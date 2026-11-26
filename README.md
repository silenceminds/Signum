# Signum

**Signum** is a self-hosted reverse proxy and multiplexed tunneling system built in **Rust** (`signum-edge`) and **C11** (`signum-agent`, `signum-ctl`). It exposes local services behind NAT or restrictive firewalls to the public internet over an outbound, mTLS-authenticated, double-encrypted **SMPv2** tunnel.

---

## 1. System Topology

```text
Public Internet ──► [ signum-edge (Rust, Linux VPS / OCI) ] :80 / :443 / :4443
                                │
                                │  TLS 1.3 mTLS (X25519MLKEM768) + SMPv2
                                │  (ChaCha20-Poly1305 + 256B Padding)
                                ▼
                    [ signum-agent (C11, Local Host) ] ──► 127.0.0.1:<local_port>
                                ▲
                                │  Loopback Pipe / Unix Socket
                    [ signum-ctl (C11, Admin CLI) ]
```

| Component | Language | Role |
| :--- | :--- | :--- |
| **`signum-edge`** | Rust (`tokio`, `rustls`, `DashMap`) | Terminates public TLS 1.3, enforces edge rules (CIDR, JWT, Webhook HMAC, rate limits), scans egress for leaked secrets, and multiplexes streams over `:4443`. |
| **`SMPv2`** | Wire Protocol | 32-byte big-endian binary framing protocol supporting up to $2^{32}$ logical streams, credit-based flow control, key rotation, and 256-byte bucket padding. |
| **`signum-agent`** | C11 (`ws2_32`/POSIX, OpenSSL 3.x) | Dials `:4443` with mTLS + SPKI pinning, decrypts frames in locked RAM (`VirtualLock`/`mlock`), wipes buffers, and forwards traffic strictly to `127.0.0.1`. |
| **`signum-ctl`** | C11 | Loopback-only admin CLI (`\\.\pipe\signum-ctl` or `/tmp/signum.sock`) for live metrics, locked-RAM request replay, and `0x0A KILL_SWITCH` teardown. |

---

## 2. SMPv2 Wire Protocol

Every frame uses a fixed **32-byte big-endian header**, followed by the **256-byte-padded ChaCha20-Poly1305 ciphertext** and **16-byte AEAD tag**:

| Offset | Field | Description |
| :--- | :--- | :--- |
| `0..2` | **Magic** | `0x53 0x47` (`"SG"`). Mismatched connections are dropped immediately. |
| `2` | **Version** | `0x02` |
| `3` | **Opcode** | `0x01 CHALLENGE`, `0x02 AUTH_PROOF`, `0x03 SESSION_GRANT`, `0x04 OPEN_STREAM`, `0x05 DATA`, `0x06 WINDOW_UPDATE`, `0x07 KEY_ROTATE`, `0x08 PING/PONG`, `0x09 CLOSE_STREAM`, `0x0A KILL_SWITCH` |
| `4..8` | **StreamID** | `uint32` logical stream ID (`0` for control frames) |
| `8..16` | **Sequence** | `uint64` strictly monotonic counter per direction (bound in AEAD AAD) |
| `16..18` | **ActualLen** | `uint16` plaintext byte count (`0..65535`) |
| `18..20` | **PaddedLen** | `uint16` ciphertext length rounded up to a 256-byte boundary |
| `20..32` | **AuthTag** | 12-byte AEAD tag prefix (paired with full 16-byte tag after payload) |

---

## 3. 20-Layer Security Architecture

| Layer | Where | Mechanism | Threat Mitigated |
| :--- | :--- | :--- | :--- |
| **1** | Edge & Agent | TLS 1.3 only (`TLS_AES_256_GCM_SHA384` / `CHACHA20_POLY1305`) | TLS downgrade & weak ciphers |
| **2** | Edge (`:4443`) | Mutual TLS (mTLS) client X.509 verification | Unauthenticated control-plane connections |
| **3** | Agent (C) | SHA-256 SPKI public key pinning | Rogue/compromised CA MITM |
| **4** | Edge & Agent | Hybrid PQ key exchange (`X25519MLKEM768`) | Harvest-now, decrypt-later |
| **5** | Edge & Agent | Inner ChaCha20-Poly1305 encryption | Plaintext exposure if TLS is inspected |
| **6** | Edge & Agent | 64-bit monotonic `Sequence` in AEAD AAD | Replay, duplication, reordering |
| **7** | Edge & Agent | 32-byte random challenge + HMAC-SHA3-256 | Static token sniffing & replay |
| **8** | Edge & Agent | 256-byte bucket frame padding | Traffic-analysis length inference |
| **9** | Edge & Agent | 15-minute / 1 GB ephemeral key rotation | Long-term key compromise |
| **10** | Edge (`:4443`) | Subdomain bound to client cert CN / DNS SAN | Subdomain hijacking |
| **11** | Edge (`:80/:443`) | Socket-level IPv4/IPv6 CIDR & ASN allowlists | Internet scanners & unauthorized regions |
| **12** | Edge (`:80/:443`) | Edge JWT (HS256) & Webhook HMAC (`X-Hub-Signature-256`) | Unauthenticated HTTP reaching localhost |
| **13** | Edge (`:80/:443`) | Strict HTTP/1.1 header validator | CL.TE / TE.CL HTTP request smuggling |
| **14** | Edge (Egress) | 64-byte sliding-window secret scanner | Accidental `.env` / PEM / DB URL leaks |
| **15** | Agent (C) | Hardcoded `127.0.0.1` destination pinning | SSRF pivoting to LAN IPs |
| **16** | Edge (`:80/:443`) | Per-IP token-bucket rate limit & 5s header timeout | Flood DoS & Slowloris |
| **17** | Agent (C) | Physical RAM locking (`VirtualLock` / `mlock`) | Key/payload paging to disk swap |
| **18** | Edge & Agent | Zero-disk execution & `SecureZeroMemory`/`explicit_bzero` | Forensic disk recovery |
| **19** | Agent (C) | Windows Job Object / Linux `prctl` + `seccomp` | Arbitrary command execution |
| **20** | Edge & Agent | 10s heartbeat dead-man's switch + `KILL_SWITCH` | Zombie tunnels after drops/breaches |
| **21** | Edge (`:80/:443`) | 512-bit (`X-Signum-Key-512`) access key + `HMAC-SHA512` (`X-Signum-Auth-512`) request signing | Unauthenticated external callers & unverified upstream requests |

---

## 3.1. Layer 21: 512-Bit Key Verification & Request Signing

To allow authorized external or otherwise unauthenticated callers to traverse a locked-down Signum tunnel safely—and to prove to your local backend that every forwarded request passed Edge validation:

1. **Generate a 512-bit (64-byte / 128-hex) Access Key**:
   ```powershell
   .\signum-edge\target\release\signum-edge.exe --gen-key-512
   ```
2. **Configure `signum-edge.toml`**:
   ```toml
   default_deny_unauthenticated = true
   require_key_512 = true
   signum_keys_512 = ["<128-hex-char-key>"]
   key_512_master_secret = "your-edge-hmac-512-signing-secret"
   ```
3. **Caller Usage**: External callers include `X-Signum-Key-512: <128-hex-char-key>` on their HTTP request. `signum-edge` validates the 512-bit key in constant time; missing or invalid keys are rejected with `401 Unauthorized`.
4. **Backend Verification (`X-Signum-Auth-512`)**: When `key_512_master_secret` is set, `signum-edge` computes an **HMAC-SHA512** signature over `host | headers` and appends `X-Signum-Auth-512: <128-hex-tag>` before forwarding the request through `SMPv2`.

---

## 4. Build Instructions

### Prerequisites
- **Rust** (`rustc` / `cargo` 1.80+)
- **C11 Compiler** (`gcc` or `clang`), **CMake** (3.16+), **Ninja** or **Make**
- **OpenSSL 3.x** (`libssl`, `libcrypto`)

### Build `signum-edge` (Rust)
```powershell
cd signum-edge
cargo build --release
```

### Build `signum-agent` & `signum-ctl` (C11)
```powershell
cd signum-agent
cmake -B build -G Ninja -DCMAKE_C_COMPILER=gcc
cmake --build build
```

---

## 5. Quick Start & Operational Commands

### 1. Generate Test mTLS Certificates & SPKI Pin
```powershell
.\scripts\gen-certs.ps1
```

### 2. Start `signum-edge`
```powershell
.\signum-edge\target\release\signum-edge.exe --config signum-edge.toml
```

### 3. Start `signum-agent`
```powershell
.\signum-agent\build\signum-agent.exe `
  --edge 127.0.0.1 --port 4443 `
  --subdomain app.signum.local --local-port 3000 `
  --ca certs\ca.crt --cert certs\client.crt --key certs\client.key `
  --pin (Get-Content certs\edge.spki) --inspect
```

### 4. Manage Live Tunnel with `signum-ctl`
```powershell
.\signum-agent\build\signum-ctl.exe status      # Live metrics & active stream count
.\signum-agent\build\signum-ctl.exe replay 1    # Replay captured request #1 to 127.0.0.1
.\signum-agent\build\signum-ctl.exe kill        # Send 0x0A KILL_SWITCH, wipe RAM, exit
```

### 5. Run End-to-End & 400-Test Stress Suites
```powershell
python .\scripts\e2e_test.py
python -u .\scripts\stress_400_test.py
```

---

## 6. Test Specifications & Verification

| Suite | Command | Scope & Coverage |
| :--- | :--- | :--- |
| **Rust Unit Tests** | `cd signum-edge && cargo test` | **4/4 passing**: HTTP request-smuggling header rejection (`rejects_smuggling_headers`), 512-bit key validation & HMAC-SHA512 signing (`verifies_and_signs_512_bit_keys`), split-chunk PEM detection (`catches_split_pem_across_chunks`), and DB credential URL detection (`catches_db_connection_string_with_credentials`). |
| **End-to-End Suite** | `python .\scripts\e2e_test.py` | Verifies static offline fallback, mTLS + SHA-256 SPKI pinning + SMPv2 GET/POST tunneling, Layer 13 smuggling rejection, Layer 14 outbound secret blocking, and `signum-ctl` (`status`, `replay`, `kill` `0x0A KILL_SWITCH`). |
| **400-Test Stress & Storm Suite** | `python -u .\scripts\stress_400_test.py` | **399 individual attack/stress vectors + Test #400 simultaneous 399-vector storm**:<br>• **99** control-plane (`:4443`) fuzz, TLS 1.2 downgrade, missing-cert mTLS, and corrupted-SMPv2 tests<br>• **80** HTTP request-smuggling & malformed header tests<br>• **80** invalid webhook HMAC (`X-Hub-Signature-256`) & `alg=none` JWT bypass attempts<br>• **60** split-chunk outbound secret-leak scans (PEM keys, `.env` credentials, DB URLs)<br>• **70** concurrent multiplexed requests (including 48 KB payloads) + **10** `signum-ctl status` calls<br>• **Test #400**: Launches all 399 vectors concurrently in a 64-worker storm, then verifies post-storm `200 OK` recovery and clean `signum-ctl kill` shutdown (`400 passed, 0 failed` verified prior to the final Layer 21 sequencing update). |

---

## 7. Co-Authors, Organization & License

* **Organization / Co-Author**: [AROM](https://github.com/AROMEmp)
* **License**: [Apache License 2.0](LICENSE)

