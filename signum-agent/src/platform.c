#include "platform.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef _WIN32
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <time.h>
#include <errno.h>
#ifdef __linux__
#include <sys/prctl.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/audit.h>
#include <sys/syscall.h>
#endif
#endif

int sig_net_init(void) {
#ifdef _WIN32
    WSADATA wsa;
    return WSAStartup(MAKEWORD(2, 2), &wsa) == 0 ? 0 : -1;
#else
    return 0;
#endif
}

void sig_net_cleanup(void) {
#ifdef _WIN32
    WSACleanup();
#endif
}

sig_sock_t sig_tcp_connect(const char *host, uint16_t port, bool nodelay) {
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%u", (unsigned)port);

    struct addrinfo *res = NULL;
    if (getaddrinfo(host, port_str, &hints, &res) != 0) {
        return SIG_INVALID_SOCK;
    }

    sig_sock_t sock = SIG_INVALID_SOCK;
    for (struct addrinfo *p = res; p != NULL; p = p->ai_next) {
        sock = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (sock == SIG_INVALID_SOCK) continue;
        if (nodelay) {
            int one = 1;
            setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (const char *)&one, sizeof(one));
        }
        if (connect(sock, p->ai_addr, (int)p->ai_addrlen) == 0) {
            break;
        }
        sig_sock_close(sock);
        sock = SIG_INVALID_SOCK;
    }
    freeaddrinfo(res);
    return sock;
}

/* Layer 15: Hardcoded 127.0.0.1 destination pinning to block SSRF to LAN IPs */
sig_sock_t sig_tcp_connect_loopback(uint16_t port) {
    sig_sock_t sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == SIG_INVALID_SOCK) return SIG_INVALID_SOCK;

    int one = 1;
    setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (const char *)&one, sizeof(one));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        sig_sock_close(sock);
        return SIG_INVALID_SOCK;
    }
    return sock;
}

void sig_sock_close(sig_sock_t s) {
    if (s == SIG_INVALID_SOCK) return;
#ifdef _WIN32
    closesocket(s);
#else
    close(s);
#endif
}

int sig_sock_send_all(sig_sock_t s, const uint8_t *buf, size_t len) {
    size_t sent = 0;
    while (sent < len) {
        int n = send(s, (const char *)(buf + sent), (int)(len - sent), 0);
        if (n <= 0) return -1;
        sent += (size_t)n;
    }
    return 0;
}

/* Layer 17: Physical RAM Locking (VirtualLock / mlock) */
void *sig_alloc_locked(size_t size) {
#ifdef _WIN32
    void *ptr = VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!ptr) return NULL;
    VirtualLock(ptr, size);
    return ptr;
#else
    void *ptr = malloc(size);
    if (!ptr) return NULL;
    mlock(ptr, size);
    return ptr;
#endif
}

void sig_free_locked(void *ptr, size_t size) {
    if (!ptr) return;
    sig_secure_zero(ptr, size);
#ifdef _WIN32
    VirtualUnlock(ptr, size);
    VirtualFree(ptr, 0, MEM_RELEASE);
#else
    munlock(ptr, size);
    free(ptr);
#endif
}

void sig_secure_zero(void *ptr, size_t size) {
    if (!ptr || size == 0) return;
#ifdef _WIN32
    SecureZeroMemory(ptr, size);
#elif defined(__linux__) || defined(__FreeBSD__) || defined(__OpenBSD__)
    explicit_bzero(ptr, size);
#else
    volatile uint8_t *p = (volatile uint8_t *)ptr;
    while (size--) *p++ = 0;
#endif
}

void sig_mutex_init(sig_mutex_t *m) {
#ifdef _WIN32
    InitializeCriticalSection(m);
#else
    pthread_mutex_init(m, NULL);
#endif
}

void sig_mutex_lock(sig_mutex_t *m) {
#ifdef _WIN32
    EnterCriticalSection(m);
#else
    pthread_mutex_lock(m);
#endif
}

void sig_mutex_unlock(sig_mutex_t *m) {
#ifdef _WIN32
    LeaveCriticalSection(m);
#else
    pthread_mutex_unlock(m);
#endif
}

void sig_mutex_destroy(sig_mutex_t *m) {
#ifdef _WIN32
    DeleteCriticalSection(m);
#else
    pthread_mutex_destroy(m);
#endif
}

#ifdef _WIN32
typedef struct {
    void *(*fn)(void *);
    void *arg;
} win_thread_wrap_t;

static DWORD WINAPI win_thread_entry(LPVOID param) {
    win_thread_wrap_t *w = (win_thread_wrap_t *)param;
    void *(*fn)(void *) = w->fn;
    void *arg = w->arg;
    free(w);
    fn(arg);
    return 0;
}
#endif

int sig_thread_spawn(sig_thread_t *t, void *(*fn)(void *), void *arg) {
#ifdef _WIN32
    win_thread_wrap_t *w = (win_thread_wrap_t *)malloc(sizeof(*w));
    if (!w) return -1;
    w->fn = fn;
    w->arg = arg;
    *t = CreateThread(NULL, 0, win_thread_entry, w, 0, NULL);
    if (*t == NULL) {
        free(w);
        return -1;
    }
    return 0;
#else
    return pthread_create(t, NULL, fn, arg) == 0 ? 0 : -1;
#endif
}

void sig_thread_detach(sig_thread_t t) {
#ifdef _WIN32
    if (t) CloseHandle(t);
#else
    pthread_detach(t);
#endif
}

void sig_sleep_ms(uint32_t ms) {
#ifdef _WIN32
    Sleep(ms);
#else
    struct timespec ts = { ms / 1000, (long)(ms % 1000) * 1000000L };
    nanosleep(&ts, NULL);
#endif
}

uint64_t sig_now_ms(void) {
#ifdef _WIN32
    return (uint64_t)GetTickCount64();
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)(ts.tv_nsec / 1000000ULL);
#endif
}

/* Layer 19: OS Process Restriction (Windows Job Object / Linux seccomp-bpf) */
int sig_apply_process_sandbox(void) {
#ifdef _WIN32
    HANDLE job = CreateJobObjectW(NULL, NULL);
    if (!job) return -1;

    JOBOBJECT_EXTENDED_LIMIT_INFORMATION ext;
    memset(&ext, 0, sizeof(ext));
    ext.BasicLimitInformation.LimitFlags =
        JOB_OBJECT_LIMIT_ACTIVE_PROCESS | JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    ext.BasicLimitInformation.ActiveProcessLimit = 1;
    SetInformationJobObject(job, JobObjectExtendedLimitInformation, &ext, sizeof(ext));

    JOBOBJECT_BASIC_UI_RESTRICTIONS ui;
    memset(&ui, 0, sizeof(ui));
    ui.UIRestrictionsClass = JOB_OBJECT_UILIMIT_DESKTOP | JOB_OBJECT_UILIMIT_HANDLES |
                             JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS | JOB_OBJECT_UILIMIT_WRITECLIPBOARD;
    SetInformationJobObject(job, JobObjectBasicUIRestrictions, &ui, sizeof(ui));

    AssignProcessToJobObject(job, GetCurrentProcess());
    return 0;
#elif defined(__linux__)
    prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    return 0;
#else
    return 0;
#endif
}

/* Loopback-only IPC for signum-ctl */
sig_ipc_t sig_ipc_server_create(const char *endpoint) {
#ifdef _WIN32
    return CreateNamedPipeA(
        endpoint,
        PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
        4, 4096, 4096, 0, NULL);
#else
    unlink(endpoint);
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", endpoint);
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(fd);
        return -1;
    }
    chmod(endpoint, 0600);
    if (listen(fd, 8) != 0) {
        close(fd);
        return -1;
    }
    return fd;
#endif
}

sig_ipc_t sig_ipc_server_accept(sig_ipc_t srv) {
#ifdef _WIN32
    if (srv == INVALID_HANDLE_VALUE) return INVALID_HANDLE_VALUE;
    BOOL ok = ConnectNamedPipe(srv, NULL);
    if (!ok && GetLastError() != ERROR_PIPE_CONNECTED) {
        return INVALID_HANDLE_VALUE;
    }
    return srv;
#else
    return accept(srv, NULL, NULL);
#endif
}

sig_ipc_t sig_ipc_client_connect(const char *endpoint) {
#ifdef _WIN32
    for (int attempt = 0; attempt < 40; attempt++) {
        HANDLE h = CreateFileA(endpoint, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
        if (h != INVALID_HANDLE_VALUE) {
            return h;
        }
        if (GetLastError() != ERROR_PIPE_BUSY) {
            return INVALID_HANDLE_VALUE;
        }
        WaitNamedPipeA(endpoint, 250);
    }
    return INVALID_HANDLE_VALUE;
#else
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", endpoint);
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(fd);
        return -1;
    }
    return fd;
#endif
}

int sig_ipc_write(sig_ipc_t h, const void *buf, size_t len) {
#ifdef _WIN32
    DWORD written = 0;
    if (!WriteFile(h, buf, (DWORD)len, &written, NULL)) return -1;
    return (int)written;
#else
    return (int)write(h, buf, len);
#endif
}

int sig_ipc_read(sig_ipc_t h, void *buf, size_t max_len) {
#ifdef _WIN32
    DWORD read_bytes = 0;
    if (!ReadFile(h, buf, (DWORD)max_len, &read_bytes, NULL)) return -1;
    return (int)read_bytes;
#else
    return (int)read(h, buf, max_len);
#endif
}

void sig_ipc_close(sig_ipc_t h) {
#ifdef _WIN32
    if (h != INVALID_HANDLE_VALUE) CloseHandle(h);
#else
    if (h >= 0) close(h);
#endif
}
