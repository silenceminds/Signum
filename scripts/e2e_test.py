import hashlib
import hmac
import http.server
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
EDGE_EXE = os.path.join(ROOT, "signum-edge", "target", "debug", "signum-edge.exe")
AGENT_EXE = os.path.join(ROOT, "signum-agent", "build", "signum-agent.exe")
CTL_EXE = os.path.join(ROOT, "signum-agent", "build", "signum-ctl.exe")
GEN_CERTS = os.path.join(ROOT, "scripts", "gen-certs.ps1")

WEBHOOK_SECRET = "super_webhook_secret_123"


def free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class BackendHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def do_GET(self):
        if self.path == "/leak":
            body = b"config_ok\n-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEAtest\n"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            # Split across writes to exercise sliding-window scanner
            self.wfile.write(body[:24])
            self.wfile.flush()
            time.sleep(0.05)
            self.wfile.write(body[24:])
            self.wfile.flush()
            return

        body = b'{"ok":true,"service":"signum-local-backend"}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        data = self.rfile.read(length) if length > 0 else b""
        resp = b"echo:" + data
        self.send_response(200)
        self.send_header("Content-Length", str(len(resp)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(resp)


def send_raw_http(port, raw_req: bytes) -> bytes:
    with socket.create_connection(("127.0.0.1", port), timeout=5) as s:
        s.sendall(raw_req)
        chunks = []
        while True:
            try:
                d = s.recv(4096)
                if not d:
                    break
                chunks.append(d)
            except socket.timeout:
                break
        return b"".join(chunks)


def main():
    for exe in (EDGE_EXE, AGENT_EXE, CTL_EXE):
        if not os.path.exists(exe):
            raise RuntimeError(f"Missing binary: {exe}")

    certs_dir = os.path.join(ROOT, "certs")
    subprocess.run(
        ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", GEN_CERTS, "-OutDir", certs_dir],
        check=True,
    )
    with open(os.path.join(certs_dir, "edge.spki"), "r", encoding="ascii") as f:
        spki_pin = f.read().strip()

    backend_port = free_port()
    http_port = free_port()
    https_port = free_port()
    ctrl_port = free_port()

    server = http.server.ThreadingHTTPServer(("127.0.0.1", backend_port), BackendHandler)
    srv_thread = threading.Thread(target=server.serve_forever, daemon=True)
    srv_thread.start()

    cfg_path = os.path.join(tempfile.gettempdir(), "signum-e2e.toml")
    with open(cfg_path, "w", encoding="utf-8") as f:
        f.write(
            f"""
public_http_addr = "127.0.0.1:{http_port}"
public_https_addr = "127.0.0.1:{https_port}"
control_addr = "127.0.0.1:{ctrl_port}"
public_cert_path = '{certs_dir.replace(chr(92), "/")}/edge.crt'
public_key_path = '{certs_dir.replace(chr(92), "/")}/edge.key'
control_cert_path = '{certs_dir.replace(chr(92), "/")}/edge.crt'
control_key_path = '{certs_dir.replace(chr(92), "/")}/edge.key'
control_ca_path = '{certs_dir.replace(chr(92), "/")}/ca.crt'
domain = "signum.local"

[subdomains."app.signum.local"]
cidr_allowlist = ["127.0.0.1/32"]
fallback_status = 503
fallback_body = "Tunnel Offline Fallback"

[subdomains."hook.signum.local"]
allowed_cn = "app.signum.local"
webhook_hmac_secret = "{WEBHOOK_SECRET}"
"""
        )

    edge_proc = subprocess.Popen([EDGE_EXE, "--config", cfg_path], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    time.sleep(1.0)

    # Test 0: Fallback response before agent connects
    fb_resp = send_raw_http(http_port, b"GET / HTTP/1.1\r\nHost: app.signum.local\r\nConnection: close\r\n\r\n")
    assert b"503 Fallback" in fb_resp and b"Tunnel Offline Fallback" in fb_resp, f"Unexpected fallback: {fb_resp!r}"
    print("[PASS] Static fallback response when agent offline")

    agent_proc = subprocess.Popen(
        [
            AGENT_EXE,
            "--edge", "127.0.0.1",
            "--port", str(ctrl_port),
            "--subdomain", "app.signum.local",
            "--local-port", str(backend_port),
            "--ca", os.path.join(certs_dir, "ca.crt"),
            "--cert", os.path.join(certs_dir, "client.crt"),
            "--key", os.path.join(certs_dir, "client.key"),
            "--pin", spki_pin,
            "--inspect",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )

    try:
        # Wait for tunnel handshake
        ok_resp = b""
        for _ in range(20):
            time.sleep(0.25)
            try:
                ok_resp = send_raw_http(http_port, b"GET /hello HTTP/1.1\r\nHost: app.signum.local\r\nConnection: close\r\n\r\n")
                if b"200 OK" in ok_resp:
                    break
            except Exception:
                pass
        assert b"200 OK" in ok_resp and b"signum-local-backend" in ok_resp, f"Tunnel GET failed: {ok_resp!r}"
        print("[PASS] End-to-end mTLS + SPKI pin + SMPv2 GET /hello")

        # Test 2: HTTP Request Smuggling rejection (Layer 13)
        smug_resp = send_raw_http(
            http_port,
            b"POST / HTTP/1.1\r\nHost: app.signum.local\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\nhello",
        )
        assert b"400 Bad Request" in smug_resp, f"Smuggling not blocked: {smug_resp!r}"
        print("[PASS] Layer 13 HTTP request smuggling rejected (400 Bad Request)")

        # Test 3: Outbound Secret Scanner (Layer 14)
        leak_resp = send_raw_http(http_port, b"GET /leak HTTP/1.1\r\nHost: app.signum.local\r\nConnection: close\r\n\r\n")
        assert b"MIIEpAIBAAKCAQEAtest" not in leak_resp, f"Secret leaked! {leak_resp!r}"
        print("[PASS] Layer 14 sliding-window secret scanner blocked PEM private key")

        # Test 4: signum-ctl status + replay + kill
        ctl_status = subprocess.check_output([CTL_EXE, "status"], text=True)
        assert "subdomain=app.signum.local" in ctl_status, f"Unexpected ctl status: {ctl_status}"
        print(f"[PASS] signum-ctl status -> {ctl_status.strip()}")

        ctl_replay = subprocess.check_output([CTL_EXE, "replay", "1"], text=True)
        assert "replayed request #1" in ctl_replay, f"Unexpected ctl replay: {ctl_replay}"
        print(f"[PASS] signum-ctl replay 1 -> {ctl_replay.strip()}")

        ctl_kill = subprocess.check_output([CTL_EXE, "kill"], text=True)
        assert "KILL_SWITCH" in ctl_kill, f"Unexpected ctl kill: {ctl_kill}"
        agent_rc = agent_proc.wait(timeout=5)
        assert agent_rc == 0, f"Agent exited with {agent_rc}"
        print("[PASS] signum-ctl kill sent 0x0A KILL_SWITCH and cleanly terminated agent")

        print("\nALL E2E SIGNUM TESTS PASSED!")
    finally:
        if agent_proc.poll() is None:
            agent_proc.terminate()
        if edge_proc.poll() is None:
            edge_proc.terminate()
        a_out, _ = agent_proc.communicate(timeout=2)
        e_out, _ = edge_proc.communicate(timeout=2)
        if a_out:
            print("=== AGENT LOG ===\n" + a_out.decode("utf-8", "replace"))
        if e_out:
            print("=== EDGE LOG ===\n" + e_out.decode("utf-8", "replace"))
        server.shutdown()


if __name__ == "__main__":
    main()
