/*
 * ============================================================
 *  Diffie-Hellman Key Exchange — SERVER  [parallelized]
 *  • Accept-loop spawns one pthread per client (detached)
 *  • DH parameters configurable at runtime
 * ============================================================
 *  Usage: ./dh_server [-p prime] [-g generator] [-P port]
 *
 *  Example (custom params):
 *    ./dh_server -p 576460752303424907 -g 2 -P 8888
 */

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <pthread.h>
#include "dh_common.h"

/* Runtime DH parameters — set from CLI in main(), read-only after that */
static uint64_t g_prime = DH_PRIME;
static uint64_t g_gen   = DH_GENERATOR;

static pthread_mutex_t csv_lock   = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t print_lock = PTHREAD_MUTEX_INITIALIZER;

static double now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1e9 + ts.tv_nsec;
}

static uint64_t gen_private_key_r(unsigned int *seed) {
    uint64_t lo = (uint64_t)(rand_r(seed) & 0xFFFFFFFF);
    uint64_t hi = (uint64_t)(rand_r(seed) & 0x1FFFFFFF);
    return (hi << 32) | lo | 1ULL;
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

static void write_stats(size_t id, double key_gen_ns, double mod_exp_ns,
                        double kdf_ns, size_t msg_count) {
    pthread_mutex_lock(&csv_lock);
    FILE *f = fopen("dh_stats.csv", "a");
    if (f) {
        fseek(f, 0, SEEK_END);
        if (ftell(f) == 0)
            fprintf(f, "role,session_id,key_gen_ns,mod_exp_ns,kdf_ns,msg_count\n");
        fprintf(f, "server,%zu,%.0f,%.0f,%.0f,%zu\n",
                id, key_gen_ns, mod_exp_ns, kdf_ns, msg_count);
        fclose(f);
    }
    pthread_mutex_unlock(&csv_lock);
}

typedef struct {
    int                fd;
    struct sockaddr_in addr;
    size_t             id;
} client_arg_t;

static void *client_handler(void *arg) {
    client_arg_t *ca = arg;
    int    fd = ca->fd;
    size_t id = ca->id;
    char   peer[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ca->addr.sin_addr, peer, sizeof(peer));
    free(ca);

    /* declare all locals up front to avoid jumping over initializers */
    unsigned int seed       = (unsigned int)(time(NULL) ^ (uintptr_t)pthread_self());
    double       key_gen_ns = 0, mod_exp_ns = 0, kdf_ns = 0;
    size_t       msg_count  = 0;
    uint8_t      key[32];
    double       t0;
    uint64_t     x, A, B;
    uint64_t     A_net, B_net;

    pthread_mutex_lock(&print_lock);
    printf("\n%s[Thread %zu]%s Client %s connected\n", MAGENTA, id, RESET, peer);
    pthread_mutex_unlock(&print_lock);

    /* ── DH Handshake ─────────────────────────────────── */
    /* -- Manual Private Key Input -- */
    pthread_mutex_lock(&print_lock);
    while (1) {
        printf("\n[Thread %zu] Enter private key (1 < x < %llu): ", id, (unsigned long long)(g_prime - 1));
        fflush(stdout);
        if (scanf("%llu", &x) != 1) {
            while (getchar() != '\n'); // clear buffer
            printf(RED "Invalid input. Enter a number.\n" RESET);
            continue;
        }
        if (x > 1 && x < (g_prime - 1)) {
            break; 
        } else {
            printf(RED "Weak or invalid key! Choose between 2 and %llu.\n" RESET, 
                   (unsigned long long)(g_prime - 2));
        }
    }
    pthread_mutex_unlock(&print_lock);
    key_gen_ns = 0; // Manual input time isn't useful for benchmarks

    t0 = now_ns();
    A  = mod_pow(g_gen, x, g_prime);
    mod_exp_ns = now_ns() - t0;

    A_net = htobe64(A);
    if (send_all(fd, &A_net, sizeof(A_net)) < 0) goto done;
    if (recv_all(fd, &B_net, sizeof(B_net)) < 0) goto done;
    B = be64toh(B_net);

    t0 = now_ns();
    derive_aes_key(mod_pow(B, x, g_prime), key);
    kdf_ns = now_ns() - t0;

    pthread_mutex_lock(&print_lock);
    printf("  %s[Thread %zu]%s Handshake done with %s\n", CYAN, id, RESET, peer);
    print_hex("  Session Key", key, 32);
    pthread_mutex_unlock(&print_lock);

    /* ── Message loop ─────────────────────────────────── */
    for (;;) {
        uint64_t nonce_net;
        uint32_t len_net;
        if (recv_all(fd, &nonce_net, sizeof(nonce_net)) < 0) break;
        if (recv_all(fd, &len_net,   sizeof(len_net))   < 0) break;
        uint64_t nonce   = be64toh(nonce_net);
        uint32_t msg_len = ntohl(len_net);
        if (msg_len == 0 || msg_len > 65536) break;

        uint8_t *buf = malloc(msg_len + 1);
        if (recv_all(fd, buf, msg_len) < 0) { free(buf); break; }
        buf[msg_len] = '\0';
        xor_cipher(key, nonce, buf, msg_len);
        msg_count++;

        pthread_mutex_lock(&print_lock);
        printf("  %s[Thread %zu | %s]%s %s\"%s\"%s\n",
               GREEN, id, peer, RESET, GREEN, (char*)buf, RESET);
        pthread_mutex_unlock(&print_lock);

        /* echo reply */
        size_t rlen = msg_len + 24;
        char *reply = malloc(rlen);
        rlen = snprintf(reply, rlen, "[echo #%zu] %s", msg_count, (char*)buf);
        free(buf);

        uint8_t *enc = malloc(rlen);
        memcpy(enc, reply, rlen);
        free(reply);

        uint64_t reply_nonce = (uint64_t)time(NULL) ^ (uint64_t)rand_r(&seed);
        xor_cipher(key, reply_nonce, enc, rlen);

        uint64_t rn_net = htobe64(reply_nonce);
        uint32_t rl_net = htonl((uint32_t)rlen);
        int ok = send_all(fd, &rn_net, sizeof(rn_net)) == 0 &&
                 send_all(fd, &rl_net, sizeof(rl_net)) == 0 &&
                 send_all(fd, enc, rlen) == 0;
        free(enc);
        if (!ok) break;
    }

    write_stats(id, key_gen_ns, mod_exp_ns, kdf_ns, msg_count);

done:
    pthread_mutex_lock(&print_lock);
    printf("  %s[Thread %zu]%s %s disconnected (%zu messages)\n",
           YELLOW, id, RESET, peer, msg_count);
    pthread_mutex_unlock(&print_lock);
    close(fd);
    return NULL;
}

int main(int argc, char *argv[]) {
    int  port = PORT;
    int  opt;

    while ((opt = getopt(argc, argv, "p:g:P:h")) != -1) {
        switch (opt) {
            case 'p': g_prime = strtoull(optarg, NULL, 10); break;
            case 'g': g_gen   = strtoull(optarg, NULL, 10); break;
            case 'P': port    = atoi(optarg);               break;
            default:
                fprintf(stderr,
                    "Usage: %s [-p prime] [-g generator] [-P port]\n"
                    "  -p  DH prime      (default: %llu)\n"
                    "  -g  DH generator  (default: %llu)\n"
                    "  -P  TCP port      (default: %d)\n",
                    argv[0], (unsigned long long)DH_PRIME,
                    (unsigned long long)DH_GENERATOR, PORT);
                return 1;
        }
    }

    print_banner("SERVER  [multi-client / parallelized]");
    printf("  %s→%s  p (prime)     = %llu\n", CYAN, RESET, (unsigned long long)g_prime);
    printf("  %s→%s  g (generator) = %llu\n", CYAN, RESET, (unsigned long long)g_gen);
    printf("  %s→%s  port          = %d\n\n",  CYAN, RESET, port);

    log_step(0, "Verifying DH parameters via Miller-Rabin...");
    if (!is_prime(g_prime)) {
        fprintf(stderr, RED "FATAL: p = %llu is NOT prime!\n" RESET,
                (unsigned long long)g_prime);
        return 1;
    }
    if (!is_prime((g_prime - 1) / 2)) {
        fprintf(stderr, RED "FATAL: p = %llu is not a SAFE prime! ((p-1)/2 not prime)\n" RESET,
                (unsigned long long)g_prime);
        return 1;
    }
    log_ok("Prime verified ✓  (safe prime: (p-1)/2 also prime)");

    log_step(1, "Setting up TCP server on port %d ...", port);
    int srv_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (srv_fd < 0) { perror("socket"); return 1; }

    int optval = 1;
    setsockopt(srv_fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

    struct sockaddr_in addr = {
        .sin_family      = AF_INET,
        .sin_addr.s_addr = INADDR_ANY,
        .sin_port        = htons(port)
    };
    if (bind(srv_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind"); return 1;
    }
    listen(srv_fd, 16);
    log_ok("Listening on port %d — multiple clients supported", port);
    printf("  %s→%s  Each connection handled in its own thread\n\n", BLUE, RESET);

    size_t next_id = 0;
    for (;;) {
        struct sockaddr_in cli_addr;
        socklen_t cli_len = sizeof(cli_addr);
        int cli_fd = accept(srv_fd, (struct sockaddr*)&cli_addr, &cli_len);
        if (cli_fd < 0) { perror("accept"); continue; }

        client_arg_t *ca = malloc(sizeof(*ca));
        ca->fd   = cli_fd;
        ca->addr = cli_addr;
        ca->id   = ++next_id;

        pthread_t t;
        pthread_create(&t, NULL, client_handler, ca);
        pthread_detach(t);
    }

    close(srv_fd);
    return 0;
}