/**
 * server.c – RSA Server
 *
 * Asks the user for two primes interactively, builds the key pair,
 * then listens on RSA_PORT for clients.
 *
 * No command-line arguments. Just run: ./server
 */
#include "rsa.h"
#include <stdarg.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

/* ── Network helpers ───────────────────────────────────────────────── */

static int recv_line(int fd, char *buf, size_t buflen) {
    size_t i = 0;
    while (i < buflen - 1) {
        char c;
        if (recv(fd, &c, 1, 0) <= 0) break;
        buf[i++] = c;
        if (c == '\n') break;
    }
    buf[i] = '\0';
    return (int)i;
}

static void send_fmt(int fd, const char *fmt, ...) {
    char buf[RSA_BUF_MAX];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    send(fd, buf, strlen(buf), 0);
}

/* ── Per-connection handler ────────────────────────────────────────── */

static void handle_client(int conn_fd, const RsaKeyPair *kp) {
    /* 1. Send public key */
    send_fmt(conn_fd, RSA_JSON_KEY_FMT, kp->e, kp->n);
    printf("[+] Public key sent  →  e=%llu,  n=%llu\n", kp->e, kp->n);

    /* 2. Receive ciphertext */
    char buf[RSA_BUF_MAX];
    if (recv_line(conn_fd, buf, sizeof buf) <= 0) {
        fprintf(stderr, "[-] No data from client.\n");
        return;
    }

    rsa_uint ciphertext;
    if (sscanf(buf, "{\"ciphertext\":%llu}", &ciphertext) != 1) {
        fprintf(stderr, "[-] Parse error: %s\n", buf);
        send_fmt(conn_fd, RSA_JSON_ERR_FMT, RSA_STATUS_STR[RSA_ERR_PARSE]);
        return;
    }
    printf("[+] Ciphertext received: %llu\n", ciphertext);

    /* 3. Decrypt */
    rsa_uint pt_int = rsa_decrypt(ciphertext, kp->d, kp->n);

    /* 4. Integer → string */
    char recovered[RSA_BUF_MAX];
    if (rsa_uint_to_str(pt_int, recovered, sizeof recovered) != RSA_OK) {
        send_fmt(conn_fd, RSA_JSON_ERR_FMT, "decoding error");
        return;
    }
    printf("[+] Decrypted block  : \"%s\"\n\n", recovered);

    /* 5. Acknowledge */
    send_fmt(conn_fd, RSA_JSON_ACK_FMT, recovered);
}

/* ── Entry point ───────────────────────────────────────────────────── */

int main(void) {
    printf("=== RSA Server ===\n\n");

    /* ── Step 1: ask user for the two primes ─────────────────────────── */
    printf("Enter two distinct prime numbers to build the RSA key pair.\n");
    printf("Tip: use primes > 10,000,000 so n is large enough for 7-char message blocks.\n");
    printf("     (e.g. 200000033 and 200000039)\n\n");

    rsa_uint p, q;
    for (;;) {
        p = rsa_prompt_prime("  Enter prime p: ");
        q = rsa_prompt_prime("  Enter prime q: ");
        if (p == q) {
            printf("  [!] p and q must be different. Try again.\n\n");
            continue;
        }
        break;
    }

    /* ── Step 2: build key pair ─────────────────────────────────────── */
    RsaKeyPair kp;
    if (rsa_build_keypair(p, q, &kp) != RSA_OK) return EXIT_FAILURE;

    printf("\n  p   = %llu\n", kp.p);
    printf("  q   = %llu\n", kp.q);
    printf("  n   = p * q = %llu\n", kp.n);
    printf("  e   = %llu  (public exponent)\n", kp.e);
    printf("  d   = %llu  (private exponent — keep secret!)\n\n", kp.d);

    /* ── Step 3: bind and listen ────────────────────────────────────── */
    int srv_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (srv_fd < 0) { perror("socket"); return EXIT_FAILURE; }

    int opt = 1;
    setsockopt(srv_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof opt);

    struct sockaddr_in addr = {
        .sin_family      = AF_INET,
        .sin_addr.s_addr = INADDR_ANY,
        .sin_port        = htons(RSA_PORT),
    };

    if (bind(srv_fd, (struct sockaddr *)&addr, sizeof addr) < 0) {
        perror("bind"); close(srv_fd); return EXIT_FAILURE;
    }
    listen(srv_fd, 5);
    printf("[*] Listening on port %d  (Ctrl-C to stop)\n\n", RSA_PORT);

    /* ── Step 4: accept loop ────────────────────────────────────────── */
    for (;;) {
        struct sockaddr_in cli;
        socklen_t cli_len = sizeof cli;
        int conn = accept(srv_fd, (struct sockaddr *)&cli, &cli_len);
        if (conn < 0) { perror("accept"); continue; }

        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &cli.sin_addr, ip, sizeof ip);
        printf("[+] Client connected: %s:%d\n", ip, ntohs(cli.sin_port));

        handle_client(conn, &kp);
        close(conn);
    }

    close(srv_fd);
    return EXIT_SUCCESS;
}