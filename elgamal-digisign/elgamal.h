#ifndef ELGAMAL_H
#define ELGAMAL_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* ─── Constants ─────────────────────────────────────────────────────────── */

#define DEFAULT_PRIME_P     23   /* small safe prime for demo               */
#define DEFAULT_GENERATOR_G  5   /* primitive root of DEFAULT_PRIME_P       */
#define MAX_MSG_LEN        256
#define SOCKET_PORT       9090

/* ─── Types ──────────────────────────────────────────────────────────────── */

typedef struct {
    uint64_t p;   /* public prime                         */
    uint64_t g;   /* generator (primitive root mod p)     */
    uint64_t y;   /* public key: y = g^x mod p            */
} PublicKey;

typedef struct {
    uint64_t p;   /* same prime as public key             */
    uint64_t g;   /* same generator                       */
    uint64_t x;   /* private key: 1 < x < p-1             */
} PrivateKey;

typedef struct {
    uint64_t r;   /* r = g^k mod p                        */
    uint64_t s;   /* s = (H(m) - x*r) * k^-1 mod (p-1)   */
} Signature;

typedef struct {
    char      message[MAX_MSG_LEN];
    Signature sig;
    PublicKey pub;
} SignedMessage;

/* ─── Math Primitives ────────────────────────────────────────────────────── */

static inline uint64_t mod_pow(uint64_t base, uint64_t exp, uint64_t mod) {
    uint64_t result = 1;
    base %= mod;
    while (exp > 0) {
        if (exp & 1) result = result * base % mod;
        base = base * base % mod;
        exp >>= 1;
    }
    return result;
}

static inline int64_t extended_gcd(int64_t a, int64_t b, int64_t *x, int64_t *y) {
    if (b == 0) { *x = 1; *y = 0; return a; }
    int64_t x1, y1;
    int64_t g = extended_gcd(b, a % b, &x1, &y1);
    *x = y1;
    *y = x1 - (a / b) * y1;
    return g;
}

static inline uint64_t mod_inverse(uint64_t a, uint64_t m) {
    int64_t x, y;
    int64_t g = extended_gcd((int64_t)a, (int64_t)m, &x, &y);
    if (g != 1) return 0;
    return (uint64_t)((x % (int64_t)m + (int64_t)m) % (int64_t)m);
}

static inline uint64_t hash_message(const char *msg, uint64_t mod) {
    uint64_t h = 0;
    while (*msg) h = (h * 31 + (unsigned char)*msg++) % mod;
    return h == 0 ? 1 : h;
}

/* Primality test (trial division — fine for demo-scale primes) */
static inline int is_prime(uint64_t n) {
    if (n < 2) return 0;
    if (n == 2) return 1;
    if (n % 2 == 0) return 0;
    for (uint64_t i = 3; i * i <= n; i += 2)
        if (n % i == 0) return 0;
    return 1;
}

/* Check g is a primitive root of Zp* by verifying order == p-1 */
static inline int is_primitive_root(uint64_t g, uint64_t p) {
    if (g < 2 || g >= p) return 0;
    uint64_t phi = p - 1, val = g;
    for (uint64_t i = 1; i < phi; ++i) {
        if (val == 1) return 0;
        val = val * g % p;
    }
    return val == 1;
}

static inline uint64_t random_k(uint64_t p) {
    uint64_t phi = p - 1, k;
    int64_t x, y;
    do { k = 2 + (uint64_t)rand() % (phi - 2); }
    while (extended_gcd((int64_t)k, (int64_t)phi, &x, &y) != 1);
    return k;
}

/* ─── Key Generation ─────────────────────────────────────────────────────── */

/* Auto: random x chosen from (1, p-1) */
static inline void elgamal_keygen(PrivateKey *priv, PublicKey *pub,
                                  uint64_t p, uint64_t g) {
    priv->p = p; priv->g = g;
    priv->x = 2 + (uint64_t)rand() % (p - 3);
    pub->p = p; pub->g = g;
    pub->y = mod_pow(g, priv->x, p);
}

/* Manual: user supplies p, g, x.
 * Returns 0 on success, -1 bad prime, -2 bad generator, -3 bad x. */
static inline int elgamal_keygen_manual(PrivateKey *priv, PublicKey *pub,
                                        uint64_t p, uint64_t g, uint64_t x) {
    if (!is_prime(p))             return -1;
    if (!is_primitive_root(g, p)) return -2;
    if (x <= 1 || x >= p - 1)    return -3;
    priv->p = p; priv->g = g; priv->x = x;
    pub->p  = p; pub->g  = g;
    pub->y  = mod_pow(g, x, p);
    return 0;
}

/* ─── Sign ───────────────────────────────────────────────────────────────── */

/* k_override == 0 → pick random k; otherwise use supplied k.
 * Returns 0 on success, -1 on failure (invalid k or signing error). */
static inline int elgamal_sign(const char *msg,
                               const PrivateKey *priv,
                               Signature *sig,
                               uint64_t k_override) {
    uint64_t phi = priv->p - 1;
    uint64_t h   = hash_message(msg, phi);
    int max_attempts = (k_override != 0) ? 1 : 100;

    for (int attempt = 0; attempt < max_attempts; ++attempt) {
        uint64_t k = (k_override != 0) ? k_override : random_k(priv->p);
        int64_t dx, dy;
        if (extended_gcd((int64_t)k, (int64_t)phi, &dx, &dy) != 1) return -1;

        uint64_t r = mod_pow(priv->g, k, priv->p);
        if (r == 0) continue;

        uint64_t k_inv = mod_inverse(k, phi);
        int64_t  xr    = (int64_t)(priv->x * r % phi);
        int64_t  diff  = ((int64_t)h - xr % (int64_t)phi + (int64_t)phi) % (int64_t)phi;
        uint64_t s     = (uint64_t)diff * k_inv % phi;
        if (s == 0) continue;

        sig->r = r; sig->s = s;
        return 0;
    }
    return -1;
}

/* ─── Verify ─────────────────────────────────────────────────────────────── */

static inline int elgamal_verify(const char *msg,
                                 const Signature *sig,
                                 const PublicKey *pub) {
    if (sig->r == 0 || sig->r >= pub->p)     return 0;
    if (sig->s == 0 || sig->s >= pub->p - 1) return 0;
    uint64_t h   = hash_message(msg, pub->p - 1);
    uint64_t lhs = mod_pow(pub->g, h, pub->p);
    uint64_t yr  = mod_pow(pub->y, sig->r, pub->p);
    uint64_t rs  = mod_pow(sig->r, sig->s, pub->p);
    return lhs == (yr * rs % pub->p);
}

/* ─── Pretty Printing ────────────────────────────────────────────────────── */

static inline void print_public_key(const PublicKey *pub) {
    printf("  PublicKey  { p=%llu, g=%llu, y=%llu }\n",
           (unsigned long long)pub->p,
           (unsigned long long)pub->g,
           (unsigned long long)pub->y);
}

static inline void print_signature(const Signature *sig) {
    printf("  Signature  { r=%llu, s=%llu }\n",
           (unsigned long long)sig->r,
           (unsigned long long)sig->s);
}

#endif /* ELGAMAL_H */
