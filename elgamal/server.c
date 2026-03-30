// p=17, a=2, b=2, G=(5,1), n=19, d=7 

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
    ll p;  
    ll a;  
    ll b;  
    ll n;  
    Point G;/* generator                    */
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
    ll d = n - 1;
    int r = 0;
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
    if (n < 2)  return 0;
    if (n == 2 || n == 3 || n == 5 || n == 7) return 1;
    if (n % 2 == 0) return 0;
   
    ll witnesses[] = {2, 3, 5, 7};
    for (int i = 0; i < 4; i++)
        if (!miller_rabin_test(n, witnesses[i])) return 0;
    return 1;
}




static Point point_at_infinity(void)
{
    Point P; P.x = 0; P.y = 0; P.inf = 1;
    return P;
}

static int point_equal(Point A, Point B)
{
    if (A.inf && B.inf) return 1;
    if (A.inf || B.inf) return 0;
    return (A.x == B.x && A.y == B.y);
}


static Point point_add(Point A, Point B, Curve *C)
{
    if (A.inf) return B;
    if (B.inf) return A;

    ll p = C->p, a = C->a;

    if (A.x == B.x) {
        if (mod(A.y + B.y, p) == 0)  
            return point_at_infinity();
       
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






static int curve_non_singular(Curve *C)
{
    ll disc = mod(4 * mod_pow(C->a, 3, C->p) + 27 * mod_pow(C->b, 2, C->p), C->p);
    return (disc != 0);
}


static int point_on_curve(Point P, Curve *C)
{
    if (P.inf) return 1;
    ll lhs = mod(P.y * P.y, C->p);
    ll rhs = mod(mod_pow(P.x, 3, C->p) + C->a * P.x + C->b, C->p);
    return (lhs == rhs);
}


static int check_generator_order(Curve *C)
{
    Point Z = scalar_mul(C->n, C->G, C);
    return Z.inf;
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


static Point decrypt_point(Ciphertext ct, ll d, Curve *C)
{
    Point dC1 = scalar_mul(d, ct.C1, C);
   
    Point neg_dC1 = dC1;
    if (!neg_dC1.inf)
        neg_dC1.y = mod(-dC1.y, C->p);
    return point_add(ct.C2, neg_dC1, C);
}


static ll brute_dlog(Point M, Curve *C, ll max_m)
{
    if (M.inf) return 0;
    Point T = C->G;
    for (ll i = 1; i <= max_m; i++) {
        if (point_equal(T, M)) return i;
        T = point_add(T, C->G, C);
    }
    return -1;
}


static Ciphertext hom_add(Ciphertext A, Ciphertext B, Curve *C)
{
    Ciphertext out;
    out.C1 = point_add(A.C1, B.C1, C);
    out.C2 = point_add(A.C2, B.C2, C);
    return out;
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


static int send_point(int fd, Point P)
{
    return send_all(fd, &P, sizeof(Point));
}


static int recv_point(int fd, Point *P)
{
    return recv_all(fd, P, sizeof(Point));
}


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
    printf("║   Homomorphic EC-ElGamal  —  SERVER                     ║\n");
    printf("╚══════════════════════════════════════════════════════════╝\n\n");

   
    printf("─── Curve Parameters ───────────────────────────────────────\n");
    printf("Enter a short-Weierstrass curve  y² = x³ + ax + b  (mod p)\n\n");

    Curve C;
   
    while (1) {
        C.p = read_ll("  Field prime p         : ");
        if (C.p < 5) { printf("  [!] p must be >= 5.\n"); continue; }
        if (!is_prime(C.p)) { printf("  [!] p is not prime.\n"); continue; }
        break;
    }
    C.a = read_ll("  Coefficient a         : ");
    C.b = read_ll("  Coefficient b         : ");

   
    if (!curve_non_singular(&C)) {
        printf("  [!] Curve is singular (4a³+27b²=0). Aborting.\n");
        return 1;
    }
    printf("  [+] Curve is non-singular.\n");

   
    while (1) {
        C.G.x   = read_ll("  Generator G.x         : ");
        C.G.y   = read_ll("  Generator G.y         : ");
        C.G.inf = 0;
        if (!point_on_curve(C.G, &C)) {
            printf("  [!] G is not on the curve.\n"); continue;
        }
        break;
    }

   
    while (1) {
        C.n = read_ll("  Order of G (n)        : ");
        if (C.n < 2) { printf("  [!] n must be >= 2.\n"); continue; }
        if (!is_prime(C.n)) { printf("  [!] n must be prime for EC-ElGamal.\n"); continue; }
        if (!check_generator_order(&C)) {
            printf("  [!] n*G ≠ O. Wrong order.\n"); continue;
        }
        printf("  [+] n*G = O  ✓\n");
        break;
    }

   
    printf("\n─── Key Generation ─────────────────────────────────────────\n");
    ll d;
    while (1) {
        d = read_ll("  Private key d  (1 < d < n) : ");
        if (d <= 1 || d >= C.n) {
            printf("  [!] d must satisfy 1 < d < n.\n"); continue;
        }
        break;
    }

    clock_gettime(CLOCK_MONOTONIC, &t0);
    Point Q = scalar_mul(d, C.G, &C); 
    clock_gettime(CLOCK_MONOTONIC, &t1);
    printf("  [+] Public key Q = d*G computed in %.4f ms\n", elapsed_ms(t0, t1));
    print_point("Q", Q);

   
    printf("\n─── Network Setup ──────────────────────────────────────────\n");
    ll port_ll;
    while (1) {
        port_ll = read_ll("  Port to listen on     : ");
        if (port_ll < 1024 || port_ll > 65535) {
            printf("  [!] Port must be in [1024, 65535].\n"); continue;
        }
        break;
    }
    int port = (int)port_ll;

   
    int srv_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (srv_fd < 0) { perror("socket"); return 1; }

    int opt = 1;
    setsockopt(srv_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port        = htons((uint16_t)port);

    if (bind(srv_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind"); close(srv_fd); return 1;
    }
    if (listen(srv_fd, 1) < 0) {
        perror("listen"); close(srv_fd); return 1;
    }
    printf("  [+] Listening on port %d …\n", port);

   
    struct sockaddr_in cli_addr;
    socklen_t cli_len = sizeof(cli_addr);

    clock_gettime(CLOCK_MONOTONIC, &t0);
    int cli_fd = accept(srv_fd, (struct sockaddr *)&cli_addr, &cli_len);
    clock_gettime(CLOCK_MONOTONIC, &t1);

    if (cli_fd < 0) { perror("accept"); close(srv_fd); return 1; }
    printf("  [+] Client connected from %s (accept: %.4f ms)\n",
           inet_ntoa(cli_addr.sin_addr), elapsed_ms(t0, t1));

   
    clock_gettime(CLOCK_MONOTONIC, &t0);

   
    if (send_all(cli_fd, &C, sizeof(Curve)) < 0) {
        fprintf(stderr, "send Curve failed\n"); goto cleanup;
    }
   
    if (send_point(cli_fd, Q) < 0) {
        fprintf(stderr, "send Q failed\n"); goto cleanup;
    }

    clock_gettime(CLOCK_MONOTONIC, &t1);
    printf("  [+] Sent curve params + public key  (%.4f ms)\n", elapsed_ms(t0, t1));

   
    printf("\n─── Receiving Ciphertexts from Client ──────────────────────\n");

    Ciphertext ct1, ct2;

    clock_gettime(CLOCK_MONOTONIC, &t0);
    if (recv_ct(cli_fd, &ct1) < 0) { fprintf(stderr, "recv ct1\n"); goto cleanup; }
    if (recv_ct(cli_fd, &ct2) < 0) { fprintf(stderr, "recv ct2\n"); goto cleanup; }
    clock_gettime(CLOCK_MONOTONIC, &t1);

    printf("  [+] Received 2 ciphertexts  (%.4f ms)\n", elapsed_ms(t0, t1));
    print_ct("Enc(m1)", ct1);
    print_ct("Enc(m2)", ct2);

   
    printf("\n─── Homomorphic Addition ───────────────────────────────────\n");
    clock_gettime(CLOCK_MONOTONIC, &t0);
    Ciphertext ct_sum = hom_add(ct1, ct2, &C);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    printf("  [+] Enc(m1) ⊕ Enc(m2) computed in %.4f ms\n", elapsed_ms(t0, t1));
    print_ct("Enc(m1+m2)", ct_sum);

   
    printf("\n─── Decryption ─────────────────────────────────────────────\n");
    clock_gettime(CLOCK_MONOTONIC, &t0);
    Point mG      = decrypt_point(ct_sum, d, &C);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    printf("  [+] Decrypted to point (m1+m2)*G in %.4f ms\n", elapsed_ms(t0, t1));
    print_point("(m1+m2)*G", mG);

    ll max_m;
    while (1) {
        max_m = read_ll("  Max DLOG search bound (brute-force m1+m2 up to): ");
        if (max_m < 1) { printf("  [!] Must be >= 1.\n"); continue; }
        break;
    }

    clock_gettime(CLOCK_MONOTONIC, &t0);
    ll m_sum = brute_dlog(mG, &C, max_m);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    printf("  [+] Brute-force DLOG completed in %.4f ms\n", elapsed_ms(t0, t1));

    if (m_sum < 0)
        printf("  [!] DLOG not found in [0, %lld]. Increase search bound.\n", max_m);
    else
        printf("  [✓] Decrypted sum  m1 + m2  =  %lld\n", m_sum);

   
    clock_gettime(CLOCK_MONOTONIC, &t0);
    if (send_all(cli_fd, &m_sum, sizeof(ll)) < 0) {
        fprintf(stderr, "send m_sum\n"); goto cleanup;
    }
    clock_gettime(CLOCK_MONOTONIC, &t1);
    printf("  [+] Sent decrypted sum to client  (%.4f ms)\n", elapsed_ms(t0, t1));

cleanup:
    close(cli_fd);
    close(srv_fd);
    printf("\n[Server] Done.\n");
    return 0;
}