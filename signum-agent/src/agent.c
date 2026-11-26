#include "platform.h"
#include "smpv2.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_STREAMS 1024
#define SCRATCH_CAP 65536

typedef struct {
    bool active;
    uint32_t stream_id;
    sig_sock_t local_sock;
    uint16_t target_port;
} local_stream_t;

typedef struct {
    const char *edge_host;
    uint16_t edge_port;
    const char *standby_host;
    uint16_t standby_port;
    const char *subdomain;
    uint16_t weight;
    uint16_t default_local_port;
    const char *ca_path;
    const char *cert_path;
    const char *key_path;
    const char *spki_pin;
    bool inspect_mode;

    signum_tls_t tls;
    smp_cipher_t tx_cipher;
    smp_cipher_t rx_cipher;
    sig_mutex_t tx_lock;
    sig_mutex_t stream_lock;
    sig_mutex_t ring_lock;

    local_stream_t streams[MAX_STREAMS];
    signum_ring_t ring;
    volatile bool running;
    volatile bool kill_requested;
    volatile uint64_t frames_tx;
    volatile uint64_t frames_rx;
    volatile uint64_t last_pong_ms;
} agent_ctx_t;

static agent_ctx_t g_agent;

static local_stream_t *find_stream(agent_ctx_t *a, uint32_t id) {
    for (int i = 0; i < MAX_STREAMS; i++) {
        if (a->streams[i].active && a->streams[i].stream_id == id) {
            return &a->streams[i];
        }
    }
    return NULL;
}

static local_stream_t *alloc_stream(agent_ctx_t *a, uint32_t id, sig_sock_t s, uint16_t port) {
    for (int i = 0; i < MAX_STREAMS; i++) {
        if (!a->streams[i].active) {
            a->streams[i].active = true;
            a->streams[i].stream_id = id;
            a->streams[i].local_sock = s;
            a->streams[i].target_port = port;
            return &a->streams[i];
        }
    }
    return NULL;
}

typedef struct {
    agent_ctx_t *agent;
    uint32_t stream_id;
    sig_sock_t local_sock;
} stream_worker_arg_t;

static void *stream_reader_thread(void *arg) {
    stream_worker_arg_t *w = (stream_worker_arg_t *)arg;
    agent_ctx_t *a = w->agent;
    uint32_t sid = w->stream_id;
    sig_sock_t sock = w->local_sock;
    free(w);

    uint8_t *buf = (uint8_t *)sig_alloc_locked(32768);
    if (!buf) {
        sig_sock_close(sock);
        return NULL;
    }

    while (a->running) {
        int n = recv(sock, (char *)buf, 32768, 0);
        if (n <= 0) break;

        sig_mutex_lock(&a->tx_lock);
        int rc = smp_write_frame(a->tls.ssl, &a->tx_cipher, SMP_OP_DATA, sid, buf, (size_t)n);
        if (rc == 0) a->frames_tx++;
        sig_mutex_unlock(&a->tx_lock);

        sig_secure_zero(buf, (size_t)n);
        if (rc != 0) break;
    }

    sig_free_locked(buf, 32768);

    sig_mutex_lock(&a->stream_lock);
    local_stream_t *st = find_stream(a, sid);
    if (st) {
        st->active = false;
        st->local_sock = SIG_INVALID_SOCK;
    }
    sig_mutex_unlock(&a->stream_lock);
    sig_sock_close(sock);

    if (a->running) {
        sig_mutex_lock(&a->tx_lock);
        smp_write_frame(a->tls.ssl, &a->tx_cipher, SMP_OP_CLOSE_STREAM, sid, NULL, 0);
        sig_mutex_unlock(&a->tx_lock);
    }
    return NULL;
}

static void *ctl_server_thread(void *arg) {
    agent_ctx_t *a = (agent_ctx_t *)arg;
    sig_ipc_t srv = sig_ipc_server_create(SIGNUM_CTL_ENDPOINT);
    if (srv == SIG_IPC_INVALID) {
        fprintf(stderr, "[signum-agent] warning: failed to bind ctl IPC\n");
        return NULL;
    }

    while (a->running) {
        sig_ipc_t cli = sig_ipc_server_accept(srv);
        if (cli == SIG_IPC_INVALID) {
            sig_sleep_ms(100);
            continue;
        }

        char cmd[256];
        int n = sig_ipc_read(cli, cmd, sizeof(cmd) - 1);
        if (n > 0) {
            cmd[n] = '\0';
            char reply[2048];
            if (strncmp(cmd, "status", 6) == 0) {
                int active_cnt = 0;
                sig_mutex_lock(&a->stream_lock);
                for (int i = 0; i < MAX_STREAMS; i++) {
                    if (a->streams[i].active) active_cnt++;
                }
                sig_mutex_unlock(&a->stream_lock);

                snprintf(reply, sizeof(reply),
                         "subdomain=%s active_streams=%d frames_tx=%llu frames_rx=%llu ring_count=%zu\n",
                         a->subdomain, active_cnt,
                         (unsigned long long)a->frames_tx,
                         (unsigned long long)a->frames_rx,
                         a->ring.count);
                sig_ipc_write(cli, reply, strlen(reply));
            } else if (strncmp(cmd, "replay ", 7) == 0) {
                uint64_t id = strtoull(cmd + 7, NULL, 10);
                ring_entry_t ent;
                sig_mutex_lock(&a->ring_lock);
                int found = ring_get_by_id(&a->ring, id, &ent);
                sig_mutex_unlock(&a->ring_lock);

                if (found == 0) {
                    sig_sock_t ls = sig_tcp_connect_loopback(ent.target_port);
                    if (ls != SIG_INVALID_SOCK) {
                        sig_sock_send_all(ls, ent.data, ent.len);
                        sig_sock_close(ls);
                        snprintf(reply, sizeof(reply), "replayed request #%llu (%zu bytes) to 127.0.0.1:%u\n",
                                 (unsigned long long)id, ent.len, ent.target_port);
                    } else {
                        snprintf(reply, sizeof(reply), "failed to connect to 127.0.0.1:%u\n", ent.target_port);
                    }
                } else {
                    snprintf(reply, sizeof(reply), "request #%llu not found in ring buffer\n", (unsigned long long)id);
                }
                sig_ipc_write(cli, reply, strlen(reply));
            } else if (strncmp(cmd, "kill", 4) == 0) {
                const char *msg = "KILL_SWITCH sent; shutting down.\n";
                sig_ipc_write(cli, msg, strlen(msg));
                a->kill_requested = true;
                a->running = false;
                sig_mutex_lock(&a->tx_lock);
                if (a->tls.ssl) {
                    smp_write_frame(a->tls.ssl, &a->tx_cipher, SMP_OP_KILL_SWITCH, 0, NULL, 0);
                    if (a->tls.sock_fd != -1) {
#ifdef _WIN32
                        shutdown((SOCKET)a->tls.sock_fd, SD_BOTH);
#else
                        shutdown(a->tls.sock_fd, SHUT_RDWR);
#endif
                    }
                }
                sig_mutex_unlock(&a->tx_lock);
            } else {
                const char *msg = "unknown command (use: status | replay <id> | kill)\n";
                sig_ipc_write(cli, msg, strlen(msg));
            }
        }
#ifdef _WIN32
        FlushFileBuffers(srv);
        DisconnectNamedPipe(srv);
#else
        sig_ipc_close(cli);
#endif
    }
#ifdef _WIN32
    sig_ipc_close(srv);
#else
    sig_ipc_close(srv);
    unlink(SIGNUM_CTL_ENDPOINT);
#endif
    return NULL;
}

static int perform_handshake(agent_ctx_t *a, const uint8_t init_key[32]) {
    smp_cipher_init(&a->rx_cipher, init_key, 0x01);
    smp_cipher_init(&a->tx_cipher, init_key, 0x02);

    uint8_t *scratch = (uint8_t *)sig_alloc_locked(SCRATCH_CAP);
    if (!scratch) return -1;

    smp_frame_t frame;
    if (smp_read_frame(a->tls.ssl, &a->rx_cipher, &frame, scratch, SCRATCH_CAP) != 0 ||
        frame.opcode != SMP_OP_CHALLENGE || frame.actual_len != 32) {
        sig_free_locked(scratch, SCRATCH_CAP);
        return -1;
    }

    size_t sub_len = strlen(a->subdomain);
    size_t msg_len = 32 + sub_len;
    uint8_t *hmac_input = (uint8_t *)sig_alloc_locked(msg_len);
    uint8_t *proof = (uint8_t *)sig_alloc_locked(34 + sub_len);
    if (!hmac_input || !proof) {
        if (hmac_input) sig_free_locked(hmac_input, msg_len);
        if (proof) sig_free_locked(proof, 34 + sub_len);
        sig_free_locked(scratch, SCRATCH_CAP);
        return -1;
    }

    memcpy(hmac_input, frame.payload, 32);
    memcpy(hmac_input + 32, a->subdomain, sub_len);

    int rc = smp_hmac_sha3_256(init_key, 32, hmac_input, msg_len, proof);
    proof[32] = (uint8_t)(a->weight >> 8);
    proof[33] = (uint8_t)(a->weight & 0xFF);
    memcpy(proof + 34, a->subdomain, sub_len);

    if (rc == 0) {
        rc = smp_write_frame(a->tls.ssl, &a->tx_cipher, SMP_OP_AUTH_PROOF, 0, proof, 34 + sub_len);
    }

    sig_free_locked(hmac_input, msg_len);
    sig_free_locked(proof, 34 + sub_len);

    if (rc != 0) {
        sig_free_locked(scratch, SCRATCH_CAP);
        return -1;
    }

    if (smp_read_frame(a->tls.ssl, &a->rx_cipher, &frame, scratch, SCRATCH_CAP) != 0 ||
        frame.opcode != SMP_OP_SESSION_GRANT) {
        sig_free_locked(scratch, SCRATCH_CAP);
        return -1;
    }

    sig_free_locked(scratch, SCRATCH_CAP);
    return 0;
}

static void run_session_loop(agent_ctx_t *a) {
    uint8_t *scratch = (uint8_t *)sig_alloc_locked(SCRATCH_CAP);
    if (!scratch) return;

    a->last_pong_ms = sig_now_ms();

    while (a->running) {
        smp_frame_t frame;
        if (smp_read_frame(a->tls.ssl, &a->rx_cipher, &frame, scratch, SCRATCH_CAP) != 0) {
            break;
        }
        a->frames_rx++;
        a->last_pong_ms = sig_now_ms();

        switch (frame.opcode) {
        case SMP_OP_OPEN_STREAM: {
            uint16_t port = a->default_local_port;
            if (frame.actual_len >= 2) {
                uint16_t p = ((uint16_t)frame.payload[0] << 8) | (uint16_t)frame.payload[1];
                if (p != 0) port = p;
            }
            sig_sock_t ls = sig_tcp_connect_loopback(port);
            if (ls == SIG_INVALID_SOCK) {
                sig_mutex_lock(&a->tx_lock);
                smp_write_frame(a->tls.ssl, &a->tx_cipher, SMP_OP_CLOSE_STREAM, frame.stream_id, NULL, 0);
                sig_mutex_unlock(&a->tx_lock);
                break;
            }
            sig_mutex_lock(&a->stream_lock);
            local_stream_t *st = alloc_stream(a, frame.stream_id, ls, port);
            sig_mutex_unlock(&a->stream_lock);
            if (!st) {
                sig_sock_close(ls);
                break;
            }
            stream_worker_arg_t *arg = (stream_worker_arg_t *)malloc(sizeof(*arg));
            if (arg) {
                arg->agent = a;
                arg->stream_id = frame.stream_id;
                arg->local_sock = ls;
                sig_thread_t th;
                if (sig_thread_spawn(&th, stream_reader_thread, arg) == 0) {
                    sig_thread_detach(th);
                } else {
                    free(arg);
                }
            }
            break;
        }
        case SMP_OP_DATA: {
            sig_sock_t ls = SIG_INVALID_SOCK;
            uint16_t port = a->default_local_port;
            sig_mutex_lock(&a->stream_lock);
            local_stream_t *st = find_stream(a, frame.stream_id);
            if (st) {
                ls = st->local_sock;
                port = st->target_port;
            }
            sig_mutex_unlock(&a->stream_lock);

            if (ls != SIG_INVALID_SOCK) {
                if (a->inspect_mode && frame.actual_len > 0) {
                    sig_mutex_lock(&a->ring_lock);
                    ring_push(&a->ring, port, frame.payload, frame.actual_len);
                    sig_mutex_unlock(&a->ring_lock);
                }
                sig_sock_send_all(ls, frame.payload, frame.actual_len);
            }
            sig_secure_zero(frame.payload, frame.actual_len);
            break;
        }
        case SMP_OP_KEY_ROTATE:
            smp_cipher_ratchet(&a->rx_cipher, frame.sequence);
            break;
        case SMP_OP_PING_PONG:
            if (frame.actual_len >= 1 && frame.payload[0] == 0x00) {
                uint8_t pong = 0x01;
                sig_mutex_lock(&a->tx_lock);
                smp_write_frame(a->tls.ssl, &a->tx_cipher, SMP_OP_PING_PONG, 0, &pong, 1);
                sig_mutex_unlock(&a->tx_lock);
            }
            break;
        case SMP_OP_CLOSE_STREAM: {
            sig_mutex_lock(&a->stream_lock);
            local_stream_t *st = find_stream(a, frame.stream_id);
            if (st) {
                sig_sock_t ls = st->local_sock;
                st->active = false;
                st->local_sock = SIG_INVALID_SOCK;
                sig_mutex_unlock(&a->stream_lock);
                sig_sock_close(ls);
            } else {
                sig_mutex_unlock(&a->stream_lock);
            }
            break;
        }
        case SMP_OP_KILL_SWITCH:
            a->kill_requested = true;
            a->running = false;
            break;
        default:
            break;
        }
    }

    sig_free_locked(scratch, SCRATCH_CAP);
}

static void print_usage(void) {
    printf("Usage: signum-agent --edge <host> --port <port> --subdomain <sub.domain> "
           "--local-port <port> --ca <ca.pem> --cert <client.crt> --key <client.key> "
           "[--pin <sha256_spki_hex>] [--standby <host:port>] [--weight <100>] [--inspect]\n");
}

int main(int argc, char **argv) {
    memset(&g_agent, 0, sizeof(g_agent));
    g_agent.edge_port = 4443;
    g_agent.weight = 100;
    g_agent.running = true;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--edge") == 0 && i + 1 < argc) g_agent.edge_host = argv[++i];
        else if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) g_agent.edge_port = (uint16_t)atoi(argv[++i]);
        else if (strcmp(argv[i], "--standby") == 0 && i + 1 < argc) g_agent.standby_host = argv[++i];
        else if (strcmp(argv[i], "--subdomain") == 0 && i + 1 < argc) g_agent.subdomain = argv[++i];
        else if (strcmp(argv[i], "--local-port") == 0 && i + 1 < argc) g_agent.default_local_port = (uint16_t)atoi(argv[++i]);
        else if (strcmp(argv[i], "--ca") == 0 && i + 1 < argc) g_agent.ca_path = argv[++i];
        else if (strcmp(argv[i], "--cert") == 0 && i + 1 < argc) g_agent.cert_path = argv[++i];
        else if (strcmp(argv[i], "--key") == 0 && i + 1 < argc) g_agent.key_path = argv[++i];
        else if (strcmp(argv[i], "--pin") == 0 && i + 1 < argc) g_agent.spki_pin = argv[++i];
        else if (strcmp(argv[i], "--weight") == 0 && i + 1 < argc) g_agent.weight = (uint16_t)atoi(argv[++i]);
        else if (strcmp(argv[i], "--inspect") == 0) g_agent.inspect_mode = true;
        else if (strcmp(argv[i], "--help") == 0) { print_usage(); return 0; }
    }

    if (!g_agent.edge_host || !g_agent.subdomain || !g_agent.default_local_port ||
        !g_agent.ca_path || !g_agent.cert_path || !g_agent.key_path) {
        print_usage();
        return 1;
    }

    sig_net_init();
    sig_mutex_init(&g_agent.tx_lock);
    sig_mutex_init(&g_agent.stream_lock);
    sig_mutex_init(&g_agent.ring_lock);
    ring_init(&g_agent.ring);

    /* Layer 19: OS Process Restriction */
    sig_apply_process_sandbox();

    sig_thread_t ctl_th;
    if (sig_thread_spawn(&ctl_th, ctl_server_thread, &g_agent) == 0) {
        sig_thread_detach(ctl_th);
    }

    bool use_standby = false;
    while (g_agent.running && !g_agent.kill_requested) {
        const char *host = (use_standby && g_agent.standby_host) ? g_agent.standby_host : g_agent.edge_host;
        uint16_t port = g_agent.edge_port;

        uint8_t init_key[32];
        printf("[signum-agent] dialing %s:%u for %s -> 127.0.0.1:%u\n",
               host, port, g_agent.subdomain, g_agent.default_local_port);
        fflush(stdout);

        if (signum_tls_connect(&g_agent.tls, host, port,
                               g_agent.ca_path, g_agent.cert_path,
                               g_agent.key_path, g_agent.spki_pin, init_key) == 0) {
            if (perform_handshake(&g_agent, init_key) == 0) {
                sig_secure_zero(init_key, sizeof(init_key));
                printf("[signum-agent] tunnel active (%s)\n", g_agent.subdomain);
                fflush(stdout);
                run_session_loop(&g_agent);
            } else {
                sig_secure_zero(init_key, sizeof(init_key));
                fprintf(stderr, "[signum-agent] SMPv2 handshake failed\n");
            }
            smp_cipher_zeroize(&g_agent.tx_cipher);
            smp_cipher_zeroize(&g_agent.rx_cipher);
            signum_tls_close(&g_agent.tls);
        } else {
            fprintf(stderr, "[signum-agent] TLS/mTLS connect failed\n");
        }

        if (g_agent.kill_requested || !g_agent.running) break;
        if (g_agent.standby_host) use_standby = !use_standby;
        sig_sleep_ms(2000);
    }

    ring_destroy(&g_agent.ring);
    sig_mutex_destroy(&g_agent.tx_lock);
    sig_mutex_destroy(&g_agent.stream_lock);
    sig_mutex_destroy(&g_agent.ring_lock);
    sig_net_cleanup();
    return 0;
}
