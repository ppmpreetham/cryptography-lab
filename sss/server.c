

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include "common.h"

static int prompt_int(const char *msg, int lo, int hi) {
    int v;
    while (1) {
        printf("%s", msg);
        fflush(stdout);
        if (scanf("%d", &v) == 1 && v >= lo && v <= hi)
            return v;
        printf("  Please enter a number between %d and %d.\n", lo, hi);
        while (getchar() != '\n');  
    }
}

static void send_msg(int fd, const Message *m) {
    if (write(fd, m, sizeof *m) != sizeof *m) {
        perror("[Server] write");
        exit(1);
    }
}

static void recv_msg(int fd, Message *m) {
    if (read(fd, m, sizeof *m) != sizeof *m) {
        perror("[Server] read");
        exit(1);
    }
}

int main(void) {
    puts("Shamir's Secret Sharing (SERVER)\n");
   
    int secret    = prompt_int("Enter the secret (1 – 2082): ", 1, PRIME - 1);
    int threshold = prompt_int("Enter threshold k (min shares to reconstruct, 2 – 10): ", 2, MAX_THRESHOLD);
    int n         = prompt_int("Enter total number of clients n (k – 10): ", threshold, MAX_SHARES);

    int coeffs[MAX_THRESHOLD];
    coeffs[0] = secret;  

    printf("\nEnter %d random polynomial coefficient(s) a[1]…a[%d] (each 1 – 2082):\n",
           threshold - 1, threshold - 1);
    for (int i = 1; i < threshold; i++) {
        char prompt[64];
        snprintf(prompt, sizeof prompt, "  a[%d] = ", i);
        coeffs[i] = prompt_int(prompt, 1, PRIME - 1);
    }

    warn_duplicate_coeffs(coeffs, threshold);

    int share_x[MAX_SHARES], share_y[MAX_SHARES];
    printf("\n[Server] Pre-computed shares:\n");
    for (int i = 0; i < n; i++) {
        share_x[i] = i + 1;
        share_y[i] = poly_eval(coeffs, threshold - 1, share_x[i], PRIME);
        printf("  Client %d → (%d, %d)\n", i + 1, share_x[i], share_y[i]);
    }
   
    unlink(SOCKET_PATH);  

    int server_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (server_fd < 0) { perror("socket"); exit(1); }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof addr);
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, SOCKET_PATH, sizeof addr.sun_path - 1);

    if (bind(server_fd, (struct sockaddr *)&addr, sizeof addr) < 0) {
        perror("bind"); exit(1);
    }
    if (listen(server_fd, MAX_SHARES) < 0) { perror("listen"); exit(1); }

    printf("\n[Server] Listening on %s\n", SOCKET_PATH);
    printf("[Server] Waiting for %d client(s) to connect…\n\n", n);

   
    int client_fds[MAX_SHARES];
    for (int i = 0; i < n; i++) {
        client_fds[i] = accept(server_fd, NULL, NULL);
        if (client_fds[i] < 0) { perror("accept"); exit(1); }

        Message m = {
            .type      = MSG_SHARE,
            .client_id = i + 1,
            .x         = share_x[i],
            .y         = share_y[i],
        };
        send_msg(client_fds[i], &m);
        printf("[Server] → Sent share (%d, %d) to Client %d\n",
               share_x[i], share_y[i], i + 1);
    }

    printf("\n[Server] All clients connected.\n");
    int k_use = prompt_int(
        "\nHow many shares to use for reconstruction? (enter k or more): ",
        threshold, n);

    printf("[Server] Requesting shares from first %d client(s)…\n\n", k_use);

    int rec_x[MAX_SHARES], rec_y[MAX_SHARES];
    for (int i = 0; i < k_use; i++) {
       
        Message req = { .type = MSG_SHARE_REQUEST, .client_id = i + 1 };
        send_msg(client_fds[i], &req);
       
        Message reply;
        recv_msg(client_fds[i], &reply);
        rec_x[i] = reply.x;
        rec_y[i] = reply.y;
        printf("[Server] ← Received share (%d, %d) from Client %d\n",
               reply.x, reply.y, reply.client_id);
    }
   
    int recovered = lagrange_reconstruct(rec_x, rec_y, k_use);
    printf("\n[Server] ══ Recovered secret = %d  (%s) ══\n",
           recovered,
           recovered == secret ? "✓ CORRECT" : "✗ WRONG — check your inputs");

    Message result_msg = {
        .type   = MSG_RESULT,
        .secret = recovered,
    };
    for (int i = 0; i < n; i++) {
        send_msg(client_fds[i], &result_msg);
        close(client_fds[i]);
    }

    close(server_fd);
    unlink(SOCKET_PATH);
    return 0;
}