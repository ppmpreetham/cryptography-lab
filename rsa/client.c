/**
 * client.c – RSA Client
 *
 * Prompts the user for a message, connects to the server on RSA_PORT,
 * receives the public key, encrypts each 7-char block, sends it, and
 * prints the server's acknowledgement.
 *
 * No command-line arguments. Just run: ./client
 */
#include "rsa.h"
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

/* ── Network helper ────────────────────────────────────────────────── */

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

/* ── Block encryption helpers ──────────────────────────────────────── */

/* MAX_BLOCK_CHARS must match RSA_CHARS_PER_BLOCK in rsa.c */
#define MAX_BLOCK_CHARS 7

/* Pack up to MAX_BLOCK_CHARS bytes of src into a rsa_uint. */
static rsa_uint pack_block(const char *src, size_t len) {
    rsa_uint v = 0;
    for (size_t i = 0; i < len; i++)
        v = (v << 8) | (unsigned char)src[i];
    return v;
}

/* Unpack a rsa_uint back into a null-terminated string. */

/* ── Entry point ───────────────────────────────────────────────────── */

int main(void) {
    printf("=== RSA Client ===\n\n");

    /* ── Step 1: get message from user ──────────────────────────────── */
    char message[RSA_MSG_MAX];
    rsa_prompt_string("  Message to send: ", message, sizeof message);

    /* ── Step 2: connect to server ──────────────────────────────────── */
    printf("\n[*] Connecting to 127.0.0.1:%d …\n", RSA_PORT);

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { perror("socket"); return EXIT_FAILURE; }

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port   = htons(RSA_PORT),
    };
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);

    if (connect(fd, (struct sockaddr *)&addr, sizeof addr) < 0) {
        perror("connect");
        fprintf(stderr, "[!] Is the server running on port %d?\n", RSA_PORT);
        close(fd);
        return EXIT_FAILURE;
    }
    printf("[+] Connected\n");

    /* ── Step 3: receive public key ─────────────────────────────────── */
    char buf[RSA_BUF_MAX];
    if (recv_line(fd, buf, sizeof buf) <= 0) {
        fprintf(stderr, "[!] No public key received\n");
        close(fd); return EXIT_FAILURE;
    }

    rsa_uint e, n;
    if (sscanf(buf, "{\"e\":%llu,\"n\":%llu}", &e, &n) != 2) {
        fprintf(stderr, "[!] Could not parse public key: %s\n", buf);
        close(fd); return EXIT_FAILURE;
    }
    printf("[+] Public key: e=%llu,  n=%llu\n", e, n);

    if (e < 2 || n < 3 || e >= n) {
        fprintf(stderr, "[!] Public key values look invalid\n");
        close(fd); return EXIT_FAILURE;
    }

    /* ── Step 4: encrypt and send the message, block by block ──────── */
    size_t msg_len   = strlen(message);
    size_t num_blocks = (msg_len + MAX_BLOCK_CHARS - 1) / MAX_BLOCK_CHARS;

    printf("[+] Sending %zu block(s) for message \"%s\"\n\n", num_blocks, message);

    size_t offset = 0;
    size_t block  = 1;
    while (offset < msg_len) {
        /* Slice at most MAX_BLOCK_CHARS chars */
        size_t blen = msg_len - offset;
        if (blen > MAX_BLOCK_CHARS) blen = MAX_BLOCK_CHARS;

        rsa_uint m = pack_block(message + offset, blen);

        /* Guard: m must be < n */
        if (m >= n) {
            fprintf(stderr,
                "[!] Block %zu integer (%llu) >= n (%llu).\n"
                "    The server's primes are too small for this message.\n"
                "    Ask the server operator to use larger primes (> 500).\n",
                block, m, n);
            close(fd); return EXIT_FAILURE;
        }

        rsa_uint ciphertext = rsa_encrypt(m, e, n);

        printf("  Block %zu/%zu  plain=\"%.*s\"  m=%llu  c=%llu\n",
               block, num_blocks,
               (int)blen, message + offset,
               m, ciphertext);

        /* Send ciphertext */
        char payload[RSA_BUF_MAX];
        snprintf(payload, sizeof payload, RSA_JSON_CT_FMT, ciphertext);
        send(fd, payload, strlen(payload), 0);

        /* Wait for server ACK before sending next block */
        if (recv_line(fd, buf, sizeof buf) <= 0) {
            fprintf(stderr, "[!] No ACK for block %zu\n", block);
            close(fd); return EXIT_FAILURE;
        }

        if (strstr(buf, "\"error\"")) {
            fprintf(stderr, "[!] Server error on block %zu: %s\n", block, buf);
            close(fd); return EXIT_FAILURE;
        }

        char decoded[RSA_BUF_MAX] = {0};
        sscanf(buf, "{\"status\":\"ok\",\"decrypted\":\"%[^\"]\"}", decoded);
        printf("  Block %zu/%zu  server_decrypted=\"%s\"  ✓\n\n",
               block, num_blocks, decoded);

        offset += blen;
        block++;

        /* Re-open connection for next block if server closes after each */
        if (offset < msg_len) {
            close(fd);
            fd = socket(AF_INET, SOCK_STREAM, 0);
            if (fd < 0) { perror("socket"); return EXIT_FAILURE; }
            if (connect(fd, (struct sockaddr *)&addr, sizeof addr) < 0) {
                perror("connect"); return EXIT_FAILURE;
            }
            /* receive public key again */
            if (recv_line(fd, buf, sizeof buf) <= 0) {
                fprintf(stderr, "[!] No public key on reconnect\n");
                close(fd); return EXIT_FAILURE;
            }
            /* (no need to re-parse; e and n don't change) */
        }
    }

    printf("[+] All blocks sent and verified. Round-trip successful ✓\n");
    close(fd);
    return EXIT_SUCCESS;
}