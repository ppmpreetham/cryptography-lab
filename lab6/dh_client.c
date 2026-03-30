/*
 * ============================================================
 *  Diffie-Hellman Key Exchange — CLIENT  [parallelized]
 *  • DH handshake (sequential)
 *  • -m "msg" : one-shot send + receive reply, then exit
 *  • No  -m   : interactive parallel chat (stdin + async recv)
 * ============================================================
 *  Usage: ./dh_client [-P port] [-p prime] [-g generator] [-m message]
 *
 *  Examples:
 *    ./dh_client -P 9999                         # interactive via attacker
 *    ./dh_client -P 8888 -m "hello"              # one-shot direct to server
 *    ./dh_client -p 576460752303424907 -g 2 -P 9999 -m "secret"
 *
 *  Backward compat: bare port number still works
 *    ./dh_client 9999
 */

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <time.h>
#include <pthread.h>
#include "dh_common.h"

static pthread_mutex_t print_lock = PTHREAD_MUTEX_INITIALIZER;

static double now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1e9 + ts.tv_nsec;
}

static uint64_t gen_private_key(void) {
    srand48(time(NULL) ^ (getpid() * 31337));
    uint64_t lo = (uint64_t)(lrand48() & 0xFFFFFFFF);
    uint64_t hi = (uint64_t)(lrand48() & 0x1FFFFFFF);
    return (hi << 32) | lo | 1ULL;
}

static int hamming64(uint64_t a, uint64_t b) {
    uint64_t diff = a ^ b;
    int cnt = 0;
    while (diff) { cnt += diff & 1; diff >>= 1; }
    return cnt;
}

static int recv_all(int fd, void *buf, size_t len) {
    size_t got = 0; uint8_t *p = buf;
    while (got < len) {
        ssize_t r = recv(fd, p + got, len - got, 0);
        if (r <= 0) return -1;
        got += r;
    }
    return 0;
}

static int send_all(int fd, const void *buf, size_t len) {
    size_t sent = 0; const uint8_t *p = buf;
    while (sent < len) {
        ssize_t s = send(fd, p + sent, len - sent, 0);
        if (s <= 0) return -1;
        sent += s;
    }
    return 0;
}

static void write_stats(double key_gen_ns, double mod_exp_ns, double kdf_ns,
                        double enc_ns, double dec_ns, size_t msg_len) {
    FILE *f = fopen("dh_stats.csv", "a");
    if (!f) return;
    fseek(f, 0, SEEK_END);
    if (ftell(f) == 0)
        fprintf(f, "role,session_id,key_gen_ns,mod_exp_ns,kdf_ns,encrypt_ns,decrypt_ns,msg_len\n");
    fprintf(f, "client,0,%.0f,%.0f,%.0f,%.0f,%.0f,%zu\n",
            key_gen_ns, mod_exp_ns, kdf_ns, enc_ns, dec_ns, msg_len);
    fclose(f);
}

/* ── Thread args ─────────────────────────────────────── */

typedef struct {
    int     fd;
    uint8_t key[32];
} chat_arg_t;

/* ── recv thread ─────────────────────────────────────── */

static void *recv_thread(void *arg) {
    chat_arg_t *a = arg;
    for (;;) {
        uint64_t nonce_net;
        uint32_t len_net;
        if (recv_all(a->fd, &nonce_net, sizeof(nonce_net)) < 0) break;
        if (recv_all(a->fd, &len_net,   sizeof(len_net))   < 0) break;
        uint32_t msg_len = ntohl(len_net);
        if (msg_len == 0 || msg_len > 65536) break;

        uint8_t *buf = malloc(msg_len + 1);
        if (recv_all(a->fd, buf, msg_len) < 0) { free(buf); break; }
        buf[msg_len] = '\0';
        xor_cipher(a->key, be64toh(nonce_net), buf, msg_len);

        pthread_mutex_lock(&print_lock);
        printf("\r  %s[SERVER]%s %s\"%s\"%s\n> ", GREEN, RESET, GREEN, (char*)buf, RESET);
        fflush(stdout);
        pthread_mutex_unlock(&print_lock);
        free(buf);
    }

    pthread_mutex_lock(&print_lock);
    printf("\n%s[CLIENT]%s Server closed the connection.\n", YELLOW, RESET);
    pthread_mutex_unlock(&print_lock);
    shutdown(a->fd, SHUT_RDWR);
    return NULL;
}

/* ── send thread ─────────────────────────────────────── */

static void *send_thread(void *arg) {
    chat_arg_t *a = arg;
    uint64_t counter    = 0;
    uint64_t base_nonce = (uint64_t)time(NULL) ^ 0xDEADBEEF87654321ULL;
    char     line[4096];

    printf("> "); fflush(stdout);
    while (fgets(line, sizeof(line), stdin)) {
        size_t len = strlen(line);
        if (len > 0 && line[len - 1] == '\n') line[--len] = '\0';
        if (len == 0) { printf("> "); fflush(stdout); continue; }
        if (strcmp(line, "quit") == 0) break;

        uint8_t *buf = malloc(len);
        memcpy(buf, line, len);

        uint64_t nonce = base_nonce ^ counter++;
        double t0 = now_ns();
        xor_cipher(a->key, nonce, buf, len);
        double enc_ns = now_ns() - t0;

        uint64_t n_net = htobe64(nonce);
        uint32_t l_net = htonl((uint32_t)len);
        int ok = send_all(a->fd, &n_net, sizeof(n_net)) == 0 &&
                 send_all(a->fd, &l_net, sizeof(l_net)) == 0 &&
                 send_all(a->fd, buf, len) == 0;
        free(buf);
        if (!ok) break;

        pthread_mutex_lock(&print_lock);
        log_info("Sent %zu bytes  (%.0f ns to encrypt)", len, enc_ns);
        pthread_mutex_unlock(&print_lock);

        printf("> "); fflush(stdout);
    }

    shutdown(a->fd, SHUT_RDWR);
    return NULL;
}

/* ── main ─────────────────────────────────────────────── */

int main(int argc, char *argv[]) {

    /* ── Parse arguments ─────────────────────────────── */
    uint64_t dh_prime = DH_PRIME;
    uint64_t dh_gen   = DH_GENERATOR;
    int      port     = PORT;
    char    *msg_arg  = NULL;   /* NULL = interactive mode */
    int      opt;

    while ((opt = getopt(argc, argv, "P:p:g:m:h")) != -1) {
        switch (opt) {
            case 'P': port     = atoi(optarg);               break;
            case 'p': dh_prime = strtoull(optarg, NULL, 10); break;
            case 'g': dh_gen   = strtoull(optarg, NULL, 10); break;
            case 'm': msg_arg  = optarg;                     break;
            default:
                fprintf(stderr,
                    "Usage: %s [-P port] [-p prime] [-g generator] [-m message]\n"
                    "  -P  Server port   (default: %d)\n"
                    "  -p  DH prime      (default: %llu)\n"
                    "  -g  DH generator  (default: %llu)\n"
                    "  -m  Message to send (one-shot mode; omit for interactive chat)\n",
                    argv[0], PORT,
                    (unsigned long long)DH_PRIME, (unsigned long long)DH_GENERATOR);
                return 1;
        }
    }
    /* backward compat: bare number after all flags = port */
    if (optind < argc) {
        int p = atoi(argv[optind]);
        if (p > 0) port = p;
    }

    print_banner("CLIENT  [parallel send/recv]");
    printf("  %s→%s  p (prime)     = %llu\n", CYAN, RESET, (unsigned long long)dh_prime);
    printf("  %s→%s  g (generator) = %llu\n", CYAN, RESET, (unsigned long long)dh_gen);
    printf("  %s→%s  port          = %d\n",    CYAN, RESET, port);
    printf("  %s→%s  mode          = %s\n\n",  CYAN, RESET,
           msg_arg ? "one-shot" : "interactive");

    /* ── Step 0: Verify prime ─────────────────────────── */
    log_step(0, "Verifying DH parameters via Miller-Rabin...");
    if (!is_prime(dh_prime) || !is_prime((dh_prime - 1) / 2)) {
        fprintf(stderr, RED "FATAL: p = %llu failed safe-prime verification!\n" RESET,
                (unsigned long long)dh_prime);
        return 1;
    }
    log_ok("Safe prime verified ✓");

    /* ── Step 1: Generate private key ─────────────────── */
    log_step(1, "Generating client private key...");
    double t0 = now_ns();
    uint64_t x_client;
    while (1) {
        printf("\n[INPUT] Enter your private key (1 < x < %llu): ", (unsigned long long)(dh_prime - 1));
        if (scanf("%llu", &x_client) != 1) {
            while (getchar() != '\n'); // Clear buffer
            printf(RED "Invalid input. Please enter a number.\n" RESET);
            continue;
        }

        if (x_client > 1 && x_client < (dh_prime - 1)) {
            break; // Key is valid
        } else {
            printf(RED "Weak or invalid key! Choose a value between 2 and %llu.\n" RESET, 
                   (unsigned long long)(dh_prime - 2));
        }
    }
    double key_gen_ns = now_ns() - t0;
    log_info("Private key x_c = %llu  (%.0f ns)", (unsigned long long)x_client, key_gen_ns);

    /* ── Step 2: Compute public key ───────────────────── */
    log_step(2, "Computing public key  B = g^x_c mod p ...");
    t0 = now_ns();
    uint64_t B = mod_pow(dh_gen, x_client, dh_prime);
    double mod_exp_ns = now_ns() - t0;
    log_info("B = %llu  (%.0f ns)", (unsigned long long)B, mod_exp_ns);

    /* ── Step 3: Connect ──────────────────────────────── */
    log_step(3, "Connecting to 127.0.0.1:%d ...", port);
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) { perror("socket"); return 1; }
    struct sockaddr_in srv = { .sin_family = AF_INET, .sin_port = htons(port) };
    inet_pton(AF_INET, "127.0.0.1", &srv.sin_addr);
    if (connect(sockfd, (struct sockaddr*)&srv, sizeof(srv)) < 0) {
        perror("connect"); return 1;
    }
    log_ok("Connected!");

    /* ── Step 4: Exchange public keys ─────────────────── */
    log_step(4, "Exchanging public keys...");
    uint64_t A_net;
    recv(sockfd, &A_net, sizeof(A_net), 0);
    uint64_t A = be64toh(A_net);
    log_info("Received A = %llu", (unsigned long long)A);

    uint64_t B_net = htobe64(B);
    send(sockfd, &B_net, sizeof(B_net), 0);
    log_info("Sent B.  Hamming(A,B) = %d/64 bits", hamming64(A, B));

    /* ── Step 5: Shared secret ───────────────────────── */
    log_step(5, "Computing shared secret  S = A^x_c mod p ...");
    uint64_t S = mod_pow(A, x_client, dh_prime);
    log_info("S = %llu", (unsigned long long)S);

    /* ── Step 6: Derive session key ───────────────────── */
    log_step(6, "Deriving 256-bit session key via KDF...");
    t0 = now_ns();
    uint8_t session_key[32];
    derive_aes_key(S, session_key);
    double kdf_ns = now_ns() - t0;
    print_hex("Session Key (256-bit)", session_key, 32);
    log_info("KDF took %.0f ns", kdf_ns);
    log_ok("Handshake complete.");

    printf("\n  %s⚠%s  No authentication → MITM-vulnerable (educational demo)\n\n",
           YELLOW, RESET);

    /* ── Step 7a: ONE-SHOT MODE (-m given) ────────────── */
    if (msg_arg) {
        log_step(7, "One-shot mode: sending \"%s\"", msg_arg);
        size_t  msg_len = strlen(msg_arg);
        uint8_t *cipher = malloc(msg_len);
        memcpy(cipher, msg_arg, msg_len);

        uint64_t nonce = (uint64_t)time(NULL) ^ 0xDEADBEEF87654321ULL;
        t0 = now_ns();
        xor_cipher(session_key, nonce, cipher, msg_len);
        double enc_ns = now_ns() - t0;

        uint64_t n_net = htobe64(nonce);
        uint32_t l_net = htonl((uint32_t)msg_len);
        send_all(sockfd, &n_net, sizeof(n_net));
        send_all(sockfd, &l_net, sizeof(l_net));
        send_all(sockfd, cipher, msg_len);
        free(cipher);
        log_info("Sent (%zu bytes, %.0f ns to encrypt)", msg_len, enc_ns);

        /* receive reply */
        log_step(8, "Waiting for reply...");
        uint64_t rn_net; uint32_t rl_net;
        recv_all(sockfd, &rn_net, sizeof(rn_net));
        recv_all(sockfd, &rl_net, sizeof(rl_net));
        uint32_t reply_len = ntohl(rl_net);

        uint8_t *reply = malloc(reply_len + 1);
        recv_all(sockfd, reply, reply_len);
        reply[reply_len] = '\0';
        t0 = now_ns();
        xor_cipher(session_key, be64toh(rn_net), reply, reply_len);
        double dec_ns = now_ns() - t0;

        log_ok("Server reply:");
        printf("  %s\"%s\"%s\n", GREEN, (char*)reply, RESET);
        log_info("Decryption took %.0f ns", dec_ns);

        write_stats(key_gen_ns, mod_exp_ns, kdf_ns, enc_ns, dec_ns, msg_len);
        free(reply);
        close(sockfd);
        printf("\n%s%s[CLIENT] Session closed.%s\n\n", BOLD, GREEN, RESET);
        return 0;
    }

    /* ── Step 7b: INTERACTIVE MODE (no -m) ────────────── */
    log_step(7, "Entering interactive chat. Type messages, \"quit\" or Ctrl-D to exit.");
    printf("  %s→%s  send_thread + recv_thread running concurrently\n\n", BLUE, RESET);

    chat_arg_t chat;
    chat.fd = sockfd;
    memcpy(chat.key, session_key, 32);

    pthread_t t_send, t_recv;
    pthread_create(&t_recv, NULL, recv_thread, &chat);
    pthread_create(&t_send, NULL, send_thread, &chat);

    pthread_join(t_send, NULL);
    pthread_join(t_recv, NULL);

    write_stats(key_gen_ns, mod_exp_ns, kdf_ns, 0, 0, 0);
    close(sockfd);
    printf("\n%s%s[CLIENT] Session closed.%s\n\n", BOLD, GREEN, RESET);
    return 0;
}