#ifndef SIGNUM_PLATFORM_H
#define SIGNUM_PLATFORM_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
typedef SOCKET sig_sock_t;
#define SIG_INVALID_SOCK INVALID_SOCKET
typedef CRITICAL_SECTION sig_mutex_t;
typedef HANDLE sig_thread_t;
typedef HANDLE sig_ipc_t;
#define SIG_IPC_INVALID INVALID_HANDLE_VALUE
#define SIGNUM_CTL_ENDPOINT "\\\\.\\pipe\\signum-ctl"
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <pthread.h>
typedef int sig_sock_t;
#define SIG_INVALID_SOCK (-1)
typedef pthread_mutex_t sig_mutex_t;
typedef pthread_t sig_thread_t;
typedef int sig_ipc_t;
#define SIG_IPC_INVALID (-1)
#define SIGNUM_CTL_ENDPOINT "/tmp/signum.sock"
#endif

int sig_net_init(void);
void sig_net_cleanup(void);

sig_sock_t sig_tcp_connect(const char *host, uint16_t port, bool nodelay);
sig_sock_t sig_tcp_connect_loopback(uint16_t port);
void sig_sock_close(sig_sock_t s);
int sig_sock_send_all(sig_sock_t s, const uint8_t *buf, size_t len);

void *sig_alloc_locked(size_t size);
void sig_free_locked(void *ptr, size_t size);
void sig_secure_zero(void *ptr, size_t size);

void sig_mutex_init(sig_mutex_t *m);
void sig_mutex_lock(sig_mutex_t *m);
void sig_mutex_unlock(sig_mutex_t *m);
void sig_mutex_destroy(sig_mutex_t *m);

int sig_thread_spawn(sig_thread_t *t, void *(*fn)(void *), void *arg);
void sig_thread_detach(sig_thread_t t);
void sig_sleep_ms(uint32_t ms);
uint64_t sig_now_ms(void);

int sig_apply_process_sandbox(void);

/* Loopback-only IPC for signum-ctl */
sig_ipc_t sig_ipc_server_create(const char *endpoint);
sig_ipc_t sig_ipc_server_accept(sig_ipc_t srv);
sig_ipc_t sig_ipc_client_connect(const char *endpoint);
int sig_ipc_write(sig_ipc_t h, const void *buf, size_t len);
int sig_ipc_read(sig_ipc_t h, void *buf, size_t max_len);
void sig_ipc_close(sig_ipc_t h);

#endif
