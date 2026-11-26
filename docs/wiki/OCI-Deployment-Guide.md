# OCI Deployment Guide

## 1. Provision an OCI Compute Instance
* **Recommended shapes**: `VM.Standard.A1.Flex` (ARM64 Ampere) or `VM.Standard.E2.1.Micro` (x86_64) running Ubuntu or Oracle Linux.
* Attach a **Reserved Public IP** and point `*.yourdomain.com` to it.

## 2. Configure VCN & Guest Firewall
1. In **OCI Console → VCN → Security Lists**, add TCP ingress rules for ports `80`, `443`, and `4443`.
2. On the Linux guest, run [firewall-linux.sh](../../scripts/firewall-linux.sh) to restrict `:4443` to your agent IP and open `:80`/`:443` in `iptables`:
   ```bash
   sudo ./scripts/firewall-linux.sh <YOUR_AGENT_IP>/32
   ```

## 3. Build & Run `signum-edge` via `systemd`
```bash
cd signum-edge && cargo build --release
sudo setcap 'cap_net_bind_service=+ep' target/release/signum-edge
```
Run under a non-root `signum` user with `AmbientCapabilities=CAP_NET_BIND_SERVICE` in your unit file.
