

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <errno.h>


#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#pragma GCC diagnostic ignored "-Wunused-function"




typedef long long          ll;
typedef unsigned long long ull;

typedef struct {
    ll x, y;
    int inf;
} Point;

typedef struct {
    ll p, a, b, n;
    Point G;
} Curve;

typedef struct {
    Point C1;
    Point C2;
} Ciphertext;




static double elapsed_ms(struct timespec t0, struct timespec t1)
{
    return (double)(t1.tv_sec - t0.tv_sec) * 1e3
         + (double)(t1.tv_nsec - t0.tv_nsec) * 1e-6;
}




static ll mod(ll a, ll m)
{
    ll r = a % m;
    return (r < 0) ? r + m : r;
}

static ll mod_pow(ll base, ll exp, ll m)
{
    ll result = 1;
    base = mod(base, m);
    while (exp > 0) {
        if (exp & 1) result = mod(result * base, m);
        base = mod(base * base, m);
        exp >>= 1;
    }
    return result;
}

static ll mod_inv(ll a, ll p)
{
    return mod_pow(mod(a, p), p - 2, p);
}




static int miller_rabin_test(ll n, ll a)
{
    if (n % a == 0) return (n == a);
    ll d = n - 1; int r = 0;
    while (d % 2 == 0) { d /= 2; r++; }
    ll x = mod_pow(a, d, n);
    if (x == 1 || x == n - 1) return 1;
    for (int i = 0; i < r - 1; i++) {
        x = mod(x * x, n);
        if (x == n - 1) return 1;
    }
    return 0;
}

static int is_prime(ll n)
{
    if (n < 2) return 0;
    if (n == 2 || n == 3 || n == 5 || n == 7) return 1;
    if (n % 2 == 0) return 0;
    ll witnesses[] = {2, 3, 5, 7};
    for (int i = 0; i < 4; i++)
        if (!miller_rabin_test(n, witnesses[i])) return 0;
    return 1;
}




static Point point_at_infinity(void)
{
    Point P; P.x = 0; P.y = 0; P.inf = 1; return P;
}

static Point point_add(Point A, Point B, Curve *C)
{
    if (A.inf) return B;
    if (B.inf) return A;

    ll p = C->p, a = C->a;

    if (A.x == B.x) {
        if (mod(A.y + B.y, p) == 0) return point_at_infinity();
        ll lam_num = mod(3 * mod(A.x * A.x, p) + a, p);
        ll lam_den = mod_inv(mod(2 * A.y, p), p);
        ll lam = mod(lam_num * lam_den, p);
        Point R;
        R.x = mod(lam * lam - 2 * A.x, p);
        R.y = mod(lam * (A.x - R.x) - A.y, p);
        R.inf = 0;
        return R;
    }

    ll lam_num = mod(B.y - A.y, p);
    ll lam_den = mod_inv(mod(B.x - A.x, p), p);
    ll lam = mod(lam_num * lam_den, p);
    Point R;
    R.x = mod(lam * lam - A.x - B.x, p);
    R.y = mod(lam * (A.x - R.x) - A.y, p);
    R.inf = 0;
    return R;
}

static Point scalar_mul(ll k, Point P, Curve *C)
{
    Point R = point_at_infinity();
    k = mod(k, C->n);
    while (k > 0) {
        if (k & 1) R = point_add(R, P, C);
        P = point_add(P, P, C);
        k >>= 1;
    }
    return R;
}




static int point_on_curve(Point P, Curve *C)
{
    if (P.inf) return 1;
    ll lhs = mod(P.y * P.y, C->p);
    ll rhs = mod(mod_pow(P.x, 3, C->p) + C->a * P.x + C->b, C->p);
    return (lhs == rhs);
}




static Ciphertext encrypt(ll m, ll r, Point Q, Curve *C)
{
    Ciphertext ct;
    ct.C1 = scalar_mul(r, C->G, C);
    Point mG = scalar_mul(m, C->G, C);
    Point rQ = scalar_mul(r, Q, C);
    ct.C2 = point_add(mG, rQ, C);
    return ct;
}




static void print_point(const char *label, Point P)
{
    if (P.inf)
        printf("  %s = (inf)\n", label);
    else
        printf("  %s = (%lld, %lld)\n", label, P.x, P.y);
}

static void print_ct(const char *label, Ciphertext ct)
{
    printf("  %s:\n", label);
    print_point("C1", ct.C1);
    print_point("C2", ct.C2);
}

static ll read_ll(const char *prompt)
{
    ll v;
    while (1) {
        printf("%s", prompt);
        fflush(stdout);
        if (scanf(" %lld", &v) == 1) return v;
        int c; while ((c = getchar()) != '\n' && c != EOF);
        printf("  [!] Invalid input, try again.\n");
    }
}




static int send_all(int fd, const void *buf, size_t len)
{
    const char *p = (const char *)buf;
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = send(fd, p + sent, len - sent, 0);
        if (n <= 0) return -1;
        sent += (size_t)n;
    }
    return 0;
}

static int recv_all(int fd, void *buf, size_t len)
{
    char *p = (char *)buf;
    size_t got = 0;
    while (got < len) {
        ssize_t n = recv(fd, p + got, len - got, 0);
        if (n <= 0) return -1;
        got += (size_t)n;
    }
    return 0;
}

static int send_point(int fd, Point P)  { return send_all(fd, &P, sizeof(Point)); }
static int recv_point(int fd, Point *P) { return recv_all(fd, P, sizeof(Point)); }

static int send_ct(int fd, Ciphertext ct)
{
    if (send_point(fd, ct.C1) < 0) return -1;
    return send_point(fd, ct.C2);
}

static int recv_ct(int fd, Ciphertext *ct)
{
    if (recv_point(fd, &ct->C1) < 0) return -1;
    return recv_point(fd, &ct->C2);
}




int main(void)
{
    struct timespec t0, t1;

    printf("╔══════════════════════════════════════════════════════════╗\n");
    printf("║   Homomorphic EC-ElGamal  —  CLIENT                     ║\n");
    printf("╚══════════════════════════════════════════════════════════╝\n\n");

   
    printf("─── Connection ─────────────────────────────────────────────\n");

    char server_ip[64];
    printf("  Server IP address      : ");
    fflush(stdout);
    if (scanf("%63s", server_ip) != 1) { fprintf(stderr, "Bad IP.\n"); return 1; }

    ll port_ll;
    while (1) {
        port_ll = read_ll("  Server port           : ");
        if (port_ll < 1024 || port_ll > 65535) {
            printf("  [!] Port must be in [1024, 65535].\n"); continue;
        }
        break;
    }
    int port = (int)port_ll;

   
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) { perror("socket"); return 1; }

    struct sockaddr_in srv;
    memset(&srv, 0, sizeof(srv));
    srv.sin_family      = AF_INET;
    srv.sin_port        = htons((uint16_t)port);
    if (inet_pton(AF_INET, server_ip, &srv.sin_addr) <= 0) {
        fprintf(stderr, "Invalid IP: %s\n", server_ip); close(sock); return 1;
    }

    printf("  Connecting to %s:%d … ", server_ip, port); fflush(stdout);
    clock_gettime(CLOCK_MONOTONIC, &t0);
    if (connect(sock, (struct sockaddr *)&srv, sizeof(srv)) < 0) {
        perror("connect"); close(sock); return 1;
    }
    clock_gettime(CLOCK_MONOTONIC, &t1);
    printf("connected  (%.4f ms)\n", elapsed_ms(t0, t1));

   
    printf("\n─── Receiving Public Parameters from Server ────────────────\n");

    Curve C;
    Point Q;

    clock_gettime(CLOCK_MONOTONIC, &t0);
    if (recv_all(sock, &C, sizeof(Curve)) < 0) {
        fprintf(stderr, "recv Curve\n"); goto cleanup;
    }
    if (recv_point(sock, &Q) < 0) {
        fprintf(stderr, "recv Q\n"); goto cleanup;
    }
    clock_gettime(CLOCK_MONOTONIC, &t1);
    printf("  [+] Received curve params + public key  (%.4f ms)\n", elapsed_ms(t0, t1));

   
    printf("  Curve: y² = x³ + %lld·x + %lld  (mod %lld)\n", C.a, C.b, C.p);
    printf("  n = %lld\n", C.n);
    print_point("G", C.G);
    print_point("Q (server pubkey)", Q);

   
    if (!is_prime(C.p)) {
        fprintf(stderr, "  [!] Received p is not prime!\n"); goto cleanup;
    }
    if (!is_prime(C.n)) {
        fprintf(stderr, "  [!] Received n is not prime!\n"); goto cleanup;
    }
    if (!point_on_curve(C.G, &C)) {
        fprintf(stderr, "  [!] Received G not on curve!\n"); goto cleanup;
    }
    if (!point_on_curve(Q, &C)) {
        fprintf(stderr, "  [!] Received Q not on curve!\n"); goto cleanup;
    }
    printf("  [+] All received parameters validated  ✓\n");

   
    printf("\n─── Plaintext & Randomness Input ───────────────────────────\n");

    ll m1, m2, r1, r2;

    while (1) {
        m1 = read_ll("  Plaintext m1  (1 ≤ m1 < n) : ");
        if (m1 < 1 || m1 >= C.n) {
            printf("  [!] m1 must be in [1, n-1].\n"); continue;
        }
        break;
    }
    while (1) {
        r1 = read_ll("  Randomness r1 (1 ≤ r1 < n) : ");
        if (r1 < 1 || r1 >= C.n) {
            printf("  [!] r1 must be in [1, n-1].\n"); continue;
        }
        break;
    }
    while (1) {
        m2 = read_ll("  Plaintext m2  (1 ≤ m2 < n) : ");
        if (m2 < 1 || m2 >= C.n) {
            printf("  [!] m2 must be in [1, n-1].\n"); continue;
        }
        break;
    }
    while (1) {
        r2 = read_ll("  Randomness r2 (1 ≤ r2 < n) : ");
        if (r2 < 1 || r2 >= C.n) {
            printf("  [!] r2 must be in [1, n-1].\n"); continue;
        }
        break;
    }

   
    printf("\n─── Encryption ─────────────────────────────────────────────\n");

    clock_gettime(CLOCK_MONOTONIC, &t0);
    Ciphertext ct1 = encrypt(m1, r1, Q, &C);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    printf("  [+] Enc(m1=%lld) computed in %.4f ms\n", m1, elapsed_ms(t0, t1));
    print_ct("Enc(m1)", ct1);

    clock_gettime(CLOCK_MONOTONIC, &t0);
    Ciphertext ct2 = encrypt(m2, r2, Q, &C);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    printf("  [+] Enc(m2=%lld) computed in %.4f ms\n", m2, elapsed_ms(t0, t1));
    print_ct("Enc(m2)", ct2);

   
    printf("\n─── Sending Ciphertexts to Server ──────────────────────────\n");
    clock_gettime(CLOCK_MONOTONIC, &t0);
    if (send_ct(sock, ct1) < 0) { fprintf(stderr, "send ct1\n"); goto cleanup; }
    if (send_ct(sock, ct2) < 0) { fprintf(stderr, "send ct2\n"); goto cleanup; }
    clock_gettime(CLOCK_MONOTONIC, &t1);
    printf("  [+] Sent 2 ciphertexts  (%.4f ms)\n", elapsed_ms(t0, t1));

   
    printf("\n─── Waiting for Server Result ──────────────────────────────\n");
    ll m_sum_server;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    if (recv_all(sock, &m_sum_server, sizeof(ll)) < 0) {
        fprintf(stderr, "recv m_sum\n"); goto cleanup;
    }
    clock_gettime(CLOCK_MONOTONIC, &t1);
    printf("  [+] Server result received  (%.4f ms)\n", elapsed_ms(t0, t1));

   
    printf("\n─── Verification ───────────────────────────────────────────\n");
    ll expected = (m1 + m2) % C.n;
    printf("  m1              = %lld\n", m1);
    printf("  m2              = %lld\n", m2);
    printf("  m1 + m2 (mod n) = %lld  (expected)\n", expected);
    printf("  Server returned = %lld\n", m_sum_server);

    if (m_sum_server == expected)
        printf("  [✓] Homomorphic property VERIFIED: Enc(m1)⊕Enc(m2) decrypts to m1+m2\n");
    else
        printf("  [✗] MISMATCH! Check inputs or search bound on server.\n");

cleanup:
    close(sock);
    printf("\n[Client] Done.\n");
    return 0;
}