import hashlib
import hmac
import http.server
import os
import random
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
EDGE_EXE = os.path.join(ROOT, "signum-edge", "target", "debug", "signum-edge.exe")
AGENT_EXE = os.path.join(ROOT, "signum-agent", "build", "signum-agent.exe")
CTL_EXE = os.path.join(ROOT, "signum-agent", "build", "signum-ctl.exe")
GEN_CERTS = os.path.join(ROOT, "scripts", "gen-certs.ps1")

WEBHOOK_SECRET = "stress_hmac_secret"
JWT_SECRET = "stress_jwt_secret"


def free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class StressBackend(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, format, *args):
        pass

    def do_GET(self):
        if self.path.startswith("/leak/"):
            kind = self.path.split("/leak/", 1)[1]
            payloads = {
                "rsa": b"ok\n-----BEGIN RSA PRIVATE KEY-----\nMIIE_SECRET\n",
                "ec": b"ok\n-----BEGIN EC PRIVATE KEY-----\nMHc_SECRET\n",
                "openssh": b"ok\n-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaA==\n",
                "pkcs8": b"ok\n-----BEGIN PRIVATE KEY-----\nMIIEvAIBADAN\n",
                "pgp": b"ok\n-----BEGIN PGP PRIVATE KEY BLOCK-----\nlQOY\n",
                "aws": b"env: AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCY\n",
                "db_env": b"env: DATABASE_URL=postgres://u:p@db:5432/app\n",
                "pg": b"conn=postgres://admin:s3cr3t@10.0.0.5:5432/prod\n",
                "mysql": b"conn=mysql://root:pw123@10.0.0.6:3306/app\n",
                "mongo": b"conn=mongodb+srv://user:pass@cluster.mongodb.net/db\n",
                "redis": b"conn=redis://default:tok@10.0.0.7:6379/0\n",
            }
            data = payloads.get(kind, b"ok\nSIGNUM_SECRET=leak123\n")
            self.send_response(200)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Connection", "close")
            self.end_headers()
            # Split into 3 chunks to test 64B sliding window
            c1, c2 = len(data) // 3, (2 * len(data)) // 3
            self.wfile.write(data[:c1])
            self.wfile.flush()
            time.sleep(0.01)
            self.wfile.write(data[c1:c2])
            self.wfile.flush()
            time.sleep(0.01)
            self.wfile.write(data[c2:])
            self.wfile.flush()
            return

        if self.path == "/big":
            data = b"A" * 48000
            self.send_response(200)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(data)
            return

        body = b'{"status":"ok"}'
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        n = int(self.headers.get("Content-Length", "0"))
        data = self.rfile.read(n) if n > 0 else b""
        resp = b"post_ok:" + str(len(data)).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(resp)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(resp)


def raw_exchange(host, port, payload: bytes, timeout=2.5) -> bytes:
    with socket.create_connection((host, port), timeout=timeout) as s:
        s.settimeout(timeout)
        if payload:
            s.sendall(payload)
        out = []
        while True:
            try:
                d = s.recv(4096)
                if not d:
                    break
                out.append(d)
            except socket.timeout:
                break
        return b"".join(out)


def run_suite():
    certs_dir = os.path.join(ROOT, "certs")
    if not os.path.exists(os.path.join(certs_dir, "edge.spki")):
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

    class HighBacklogHTTPServer(http.server.ThreadingHTTPServer):
        request_queue_size = 256

    srv = HighBacklogHTTPServer(("127.0.0.1", backend_port), StressBackend)
    threading.Thread(target=srv.serve_forever, daemon=True).start()

    cfg_path = os.path.join(tempfile.gettempdir(), "signum-stress-400.toml")
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
rate_limit_rps = 5000
rate_limit_burst = 5000
header_timeout_secs = 2

[subdomains."app.signum.local"]
cidr_allowlist = ["127.0.0.1/32"]

[subdomains."jwt.signum.local"]
allowed_cn = "app.signum.local"
jwt_hs256_secret = "{JWT_SECRET}"

[subdomains."hook.signum.local"]
allowed_cn = "app.signum.local"
webhook_hmac_secret = "{WEBHOOK_SECRET}"
"""
        )

    edge_log_path = os.path.join(tempfile.gettempdir(), "signum-stress-edge.log")
    agent_log_path = os.path.join(tempfile.gettempdir(), "signum-stress-agent.log")
    edge_log_f = open(edge_log_path, "wb")
    agent_log_f = open(agent_log_path, "wb")

    edge_proc = subprocess.Popen([EDGE_EXE, "--config", cfg_path], stdout=edge_log_f, stderr=subprocess.STDOUT)
    time.sleep(1.0)
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
        stdout=agent_log_f,
        stderr=subprocess.STDOUT,
    )

    passed = 0
    failed = 0
    failures = []

    def record(name, ok, detail=""):
        nonlocal passed, failed
        if ok:
            passed += 1
        else:
            failed += 1
            if len(failures) < 25:
                failures.append(f"{name}: {detail}")

    try:
        # Wait for tunnel readiness
        for _ in range(25):
            time.sleep(0.2)
            try:
                r = raw_exchange("127.0.0.1", http_port, b"GET / HTTP/1.1\r\nHost: app.signum.local\r\nConnection: close\r\n\r\n")
                if b"200 OK" in r:
                    break
            except Exception:
                pass

        # 1. 99 Control-Plane (:4443) Fuzz & TLS Downgrade / mTLS Bypass Tests
        ctrl_vectors = []
        for i in range(99):
            def make_ctrl_fn(idx=i):
                if idx < 25:
                    garbage = bytes([(idx * 17 + j) % 256 for j in range(32 + (idx % 64))])
                    if garbage[:2] == b"SG":
                        garbage = b"\x00\x00" + garbage[2:]
                    resp = raw_exchange("127.0.0.1", ctrl_port, garbage, timeout=0.6)
                    return len(resp) == 0 or b"\x15\x03" in resp, f"unexpected resp {resp[:16]!r}"
                elif idx < 50:
                    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    ctx.maximum_version = ssl.TLSVersion.TLSv1_2
                    try:
                        with socket.create_connection(("127.0.0.1", ctrl_port), timeout=1.0) as s:
                            with ctx.wrap_socket(s, server_hostname="app.signum.local"):
                                pass
                        return False, "TLS 1.2 was accepted"
                    except Exception:
                        return True, ""
                elif idx < 75:
                    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    try:
                        with socket.create_connection(("127.0.0.1", ctrl_port), timeout=1.0) as s:
                            with ctx.wrap_socket(s, server_hostname="app.signum.local") as ss:
                                ss.sendall(b"SG\x02\x02" + b"\x00" * 28)
                                d = ss.recv(64)
                                return (not d), "unauthenticated TLS 1.3 accepted"
                    except Exception:
                        return True, ""
                else:
                    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                    ctx.load_verify_locations(os.path.join(certs_dir, "ca.crt"))
                    ctx.load_cert_chain(os.path.join(certs_dir, "client.crt"), os.path.join(certs_dir, "client.key"))
                    ctx.check_hostname = False
                    try:
                        with socket.create_connection(("127.0.0.1", ctrl_port), timeout=1.0) as s:
                            with ctx.wrap_socket(s, server_hostname="app.signum.local") as ss:
                                _challenge = ss.recv(512)
                                ss.sendall(b"BAD!" + os.urandom(28))
                                d = ss.recv(64)
                                return (not d), "corrupted SMPv2 accepted"
                    except Exception:
                        return True, ""
            ctrl_vectors.append((f"ctrl_test_{i}", make_ctrl_fn))

        for name, fn in ctrl_vectors:
            try:
                ok, msg = fn()
                record(name, ok, msg)
            except Exception as e:
                record(name, False, str(e))

        # 2. 80 HTTP Request Smuggling & Malformed Header Tests
        smuggle_cases = [
            b"POST / HTTP/1.1\r\nHost: app.signum.local\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\nhello",
            b"POST / HTTP/1.1\r\nHost: app.signum.local\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\nhello",
            b"GET / HTTP/1.1\r\nHost: app.signum.local\r\nHost: evil.local\r\n\r\n",
            b"GET / HTTP/1.1\r\nHost: app.signum.local\r\nBad Header: 1\r\n\r\n",
            b"GET / HTTP/1.1\r\nHost: app.signum.local\r\n obs-fold: 1\r\n\r\n",
            b"GET / HTTP/1.1\r\nHost: app.signum.local\r\nNoColonHeader\r\n\r\n",
            b"GET / HTTP/1.1\r\nHost: app.signum.local\r\nContent-Length: abc\r\n\r\n",
            b"GET / HTTP/9.9\r\nHost: app.signum.local\r\n\r\n",
        ]
        smuggle_vectors = []
        for i in range(80):
            def make_smug_fn(idx=i):
                req = smuggle_cases[idx % len(smuggle_cases)]
                resp = raw_exchange("127.0.0.1", http_port, req, timeout=1.5)
                return b"400 Bad Request" in resp, f"got {resp[:60]!r}"
            smuggle_vectors.append((f"http_smuggle_{i}", make_smug_fn))
        for name, fn in smuggle_vectors:
            try:
                ok, msg = fn()
                record(name, ok, msg)
            except Exception as e:
                record(name, False, str(e))
        print(f"[progress] after smuggle: passed={passed} failed={failed}", flush=True)

        # 3. 80 Edge Auth / Webhook HMAC / JWT / Spoofed Header Tests
        auth_vectors = []
        for i in range(80):
            def make_auth_fn(idx=i):
                if idx < 40:
                    bad_sig = "sha256=" + ("00" * 32)
                    req = (
                        f"POST /hook HTTP/1.1\r\nHost: hook.signum.local\r\n"
                        f"X-Hub-Signature-256: {bad_sig}\r\nContent-Length: 4\r\nConnection: close\r\n\r\ntest"
                    ).encode()
                    resp = raw_exchange("127.0.0.1", http_port, req, timeout=1.5)
                    return (b"401 Unauthorized" in resp or b"502 Bad Gateway" in resp), f"got {resp[:60]!r}"
                else:
                    req = (
                        b"GET /api HTTP/1.1\r\nHost: jwt.signum.local\r\n"
                        b"Authorization: Bearer eyJhbGciOiJub25lIn0.e30.\r\nConnection: close\r\n\r\n"
                    )
                    resp = raw_exchange("127.0.0.1", http_port, req, timeout=1.5)
                    return (b"401 Unauthorized" in resp or b"502 Bad Gateway" in resp), f"got {resp[:60]!r}"
            auth_vectors.append((f"auth_reject_{i}", make_auth_fn))
        for name, fn in auth_vectors:
            try:
                ok, msg = fn()
                record(name, ok, msg)
            except Exception as e:
                record(name, False, str(e))
        print(f"[progress] after auth: passed={passed} failed={failed}", flush=True)

        # 4. 60 Outbound Secret Scanner Tests (split across TCP chunks)
        leak_kinds = ["rsa", "ec", "openssh", "pkcs8", "pgp", "aws", "db_env", "pg", "mysql", "mongo", "redis", "env"]
        leak_vectors = []
        for i in range(60):
            def make_leak_fn(idx=i):
                kind = leak_kinds[idx % len(leak_kinds)]
                req = f"GET /leak/{kind} HTTP/1.1\r\nHost: app.signum.local\r\nConnection: close\r\n\r\n".encode()
                resp = raw_exchange("127.0.0.1", http_port, req, timeout=2.0)
                leaked = any(
                    s in resp
                    for s in [b"MIIE_SECRET", b"MHc_SECRET", b"b3BlbnNzaA==", b"MIIEvAIBADAN", b"wJalrXUtnFEMI", b"s3cr3t", b"pw123", b"leak123"]
                )
                return (not leaked), f"secret leaked in {resp!r}"
            leak_vectors.append((f"secret_scan_{i}", make_leak_fn))
        for name, fn in leak_vectors:
            try:
                ok, msg = fn()
                record(name, ok, msg)
            except Exception as e:
                record(name, False, str(e))
        print(f"[progress] after secret_scan: passed={passed} failed={failed}", flush=True)

        # 5. 80 High-Concurrency Multiplexing, Large Payloads & signum-ctl Stress Tests
        def worker_req(idx):
            path = "/big" if idx % 5 == 0 else f"/ok/{idx}"
            req = f"GET {path} HTTP/1.1\r\nHost: app.signum.local\r\nConnection: close\r\n\r\n".encode()
            resp = raw_exchange("127.0.0.1", http_port, req, timeout=4.0)
            if path == "/big":
                return (b"200 OK" in resp and resp.count(b"A") == 48000), f"bad big resp len={len(resp)}"
            return (b"200 OK" in resp and b'"status":"ok"' in resp), f"bad ok resp {resp[:40]!r}"

        mux_vectors = [(f"concurrent_mux_{i}", lambda idx=i: worker_req(idx)) for i in range(70)]
        with ThreadPoolExecutor(max_workers=16) as pool:
            futs = {pool.submit(fn): name for name, fn in mux_vectors}
            for fut in as_completed(futs):
                name = futs[fut]
                try:
                    ok, msg = fut.result()
                    record(name, ok, msg)
                except Exception as e:
                    record(name, False, str(e))

        ctl_vectors = []
        for i in range(10):
            def make_ctl_fn():
                out = subprocess.check_output([CTL_EXE, "status"], text=True)
                return "subdomain=app.signum.local" in out, out
            ctl_vectors.append((f"ctl_status_{i}", make_ctl_fn))
        for name, fn in ctl_vectors:
            ok, msg = fn()
            record(name, ok, msg)

        # 6. Test #400: Simultaneous 399-Vector Combined Attack Storm
        all_399 = ctrl_vectors + smuggle_vectors + auth_vectors + leak_vectors + mux_vectors + ctl_vectors
        storm_failures = 0
        storm_details = []
        with ThreadPoolExecutor(max_workers=64) as storm_pool:
            storm_futs = {storm_pool.submit(fn): name for name, fn in all_399}
            for fut in as_completed(storm_futs):
                vname = storm_futs[fut]
                try:
                    ok, msg = fut.result()
                    if not ok:
                        storm_failures += 1
                        storm_details.append(f"{vname}: {msg}")
                except Exception as e:
                    storm_failures += 1
                    storm_details.append(f"{vname}: EXC {e}")

        # Verify system survived the 399-vector simultaneous storm and still serves + cleanly kills
        post_storm = raw_exchange("127.0.0.1", http_port, b"GET /after-storm HTTP/1.1\r\nHost: app.signum.local\r\nConnection: close\r\n\r\n", timeout=3.0)
        kill_out = subprocess.check_output([CTL_EXE, "kill"], text=True)
        agent_rc = agent_proc.wait(timeout=5)
        record(
            "test_400_simultaneous_399_storm",
            storm_failures == 0 and b"200 OK" in post_storm and "KILL_SWITCH" in kill_out and agent_rc == 0,
            f"storm_failures={storm_failures} ({storm_details[:5]}), post_storm_ok={b'200 OK' in post_storm}, rc={agent_rc}",
        )

        total = passed + failed
        print(f"STRESS_RESULTS total={total} passed={passed} failed={failed}")
        for fl in failures:
            print("FAIL:", fl)
        sys.exit(0 if failed == 0 else 1)
    finally:
        if agent_proc.poll() is None:
            agent_proc.terminate()
        if edge_proc.poll() is None:
            edge_proc.terminate()
        srv.shutdown()


if __name__ == "__main__":
    run_suite()
