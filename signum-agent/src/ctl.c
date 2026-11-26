#include "platform.h"
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("Usage: signum-ctl <status | replay <id> | kill>\n");
        return 1;
    }

    char cmd[256];
    if (strcmp(argv[1], "replay") == 0 && argc >= 3) {
        snprintf(cmd, sizeof(cmd), "replay %s", argv[2]);
    } else {
        snprintf(cmd, sizeof(cmd), "%s", argv[1]);
    }

    sig_ipc_t h = sig_ipc_client_connect(SIGNUM_CTL_ENDPOINT);
    if (h == SIG_IPC_INVALID) {
        fprintf(stderr, "[signum-ctl] failed to connect to %s (is signum-agent running?)\n",
                SIGNUM_CTL_ENDPOINT);
        return 1;
    }

    if (sig_ipc_write(h, cmd, strlen(cmd)) < 0) {
        fprintf(stderr, "[signum-ctl] write failed\n");
        sig_ipc_close(h);
        return 1;
    }

    char resp[2048];
    int n = sig_ipc_read(h, resp, sizeof(resp) - 1);
    if (n > 0) {
        resp[n] = '\0';
        printf("%s", resp);
    }

    sig_ipc_close(h);
    return 0;
}
