/*
 * server.c — ElGamal Signature Demo Server
 *
 * Listens for incoming signed messages, verifies each one using the
 * sender's embedded public key, and reports the result.
 *
 * Build:  gcc -Wall -Wextra -o server server.c
 * Run:    ./server
 */

#include "protocol.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

/* ─── Banner ─────────────────────────────────────────────────────────────── */

static void print_banner(void) {
    puts("\n╔══════════════════════════════════════════════════╗");
    puts("║   ElGamal Digital Signature — VERIFICATION SRV  ║");
    puts("╚══════════════════════════════════════════════════╝");
    printf("  Listening on port %d …\n\n", SOCKET_PORT);
}

/* ─── Handle one client connection ──────────────────────────────────────── */

static void handle_client(int client_fd, struct sockaddr_in *addr) {
    char ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &addr->sin_addr, ip, sizeof(ip));
    printf("[+] Connection from %s:%d\n", ip, ntohs(addr->sin_port));

    SignedMessage sm;

    while (recv_signed_message(client_fd, &sm) == 0) {
        puts("─────────────────────────────────────────────────");
        printf("  Message   : \"%s\"\n", sm.message);
        print_public_key(&sm.pub);
        print_signature(&sm.sig);

        int valid = elgamal_verify(sm.message, &sm.sig, &sm.pub);

        if (valid) {
            puts("  Result    : ✓  SIGNATURE VALID — message authentic");
        } else {
            puts("  Result    : ✗  SIGNATURE INVALID — message rejected");
        }
    }

    printf("[-] Client %s disconnected\n\n", ip);
    close(client_fd);
}

/* ─── Main ───────────────────────────────────────────────────────────────── */

int main(void) {
    setvbuf(stdout, NULL, _IOLBF, 0); /* line-buffered output */
    print_banner();

    int server_fd = create_server_socket(SOCKET_PORT);
    if (server_fd < 0) {
        perror("create_server_socket");
        return EXIT_FAILURE;
    }

    for (;;) {
        struct sockaddr_in client_addr;
        socklen_t addr_len = sizeof(client_addr);
        int client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &addr_len);
        if (client_fd < 0) {
            perror("accept");
            continue;
        }
        handle_client(client_fd, &client_addr);
    }

    close(server_fd);
    return EXIT_SUCCESS;
}
