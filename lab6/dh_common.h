#ifndef DH_COMMON_H
#define DH_COMMON_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <math.h>

// ============================================================
//  ANSI Colors for impressive terminal output
// ============================================================
#define RESET   "\033[0m"
#define RED     "\033[31m"
#define GREEN   "\033[32m"
#define YELLOW  "\033[33m"
#define BLUE    "\033[34m"
#define MAGENTA "\033[35m"
#define CYAN    "\033[36m"
#define BOLD    "\033[1m"
#define DIM     "\033[2m"

// ============================================================
//  DH Parameters  (RFC-3526 Group-14 truncated for demo)
//  In production use 2048-bit+ prime; here we use 64-bit safe prime
//  for easy demo without OpenSSL.
// ============================================================

// A safe prime: p = 2q+1 where q is also prime (18-digit decimal)
// p = 0xFFFFFFFFFFFFFFC5  (close to 2^64, simplified for portability)
// For a classroom demo we use a well-known 61-bit safe prime:
//   p = 2305843009213693951  (= 2^61 - 1,  Mersenne prime, safe too)
// Generator g=2 is a primitive root mod p for this prime.

#define DH_PRIME  576460752303424907ULL    // 60-bit safe prime (2q+1, q also prime)
#define DH_GENERATOR 2ULL
#define PORT      8888
#define BUFFER_SIZE 4096
#define KEY_SIZE  256   // bits for AES key derivation display

// ============================================================
//  128-bit unsigned for intermediate multiplication
// ============================================================
typedef unsigned __int128 uint128_t;

// ============================================================
//  Utility: modular exponentiation  (base^exp % mod)
//  Uses binary exponentiation O(log exp), prevents overflow
//  via 128-bit intermediate products.
// ============================================================
static inline uint64_t mod_pow(uint64_t base, uint64_t exp, uint64_t mod) {
    uint64_t result = 1;
    base %= mod;
    while (exp > 0) {
        if (exp & 1)
            result = (uint128_t)result * base % mod;
        exp >>= 1;
        base = (uint128_t)base * base % mod;
    }
    return result;
}

// ============================================================
//  Miller-Rabin Primality Test (deterministic for n < 3.3×10^24)
// ============================================================
static inline int miller_rabin_witness(uint64_t n, uint64_t a, uint64_t d, int r) {
    uint64_t x = mod_pow(a, d, n);
    if (x == 1 || x == n - 1) return 0;
    for (int i = 0; i < r - 1; i++) {
        x = (uint128_t)x * x % n;
        if (x == n - 1) return 0;
    }
    return 1; // composite
}

static inline int is_prime(uint64_t n) {
    if (n < 2) return 0;
    if (n == 2 || n == 3 || n == 5 || n == 7) return 1;
    if (n % 2 == 0) return 0;
    uint64_t d = n - 1; int r = 0;
    while (d % 2 == 0) { d >>= 1; r++; }
    // Deterministic witnesses for n < 3,317,044,064,679,887,385,961,981
    uint64_t witnesses[] = {2,3,5,7,11,13,17,19,23,29,31,37};
    for (int i = 0; i < 12; i++) {
        if (witnesses[i] >= n) continue;
        if (miller_rabin_witness(n, witnesses[i], d, r)) return 0;
    }
    return 1;
}

// ============================================================
//  Simple SHA-256-like mixing for key derivation (demo KDF)
//  Real code should use SHA-256 from a crypto library.
// ============================================================
static inline void derive_aes_key(uint64_t shared_secret, uint8_t key[32]) {
    // Feistel-like mixing rounds
    uint64_t h0 = shared_secret ^ 0x6a09e667bb67ae85ULL;
    uint64_t h1 = shared_secret ^ 0x3c6ef372a54ff53aULL;
    for (int i = 0; i < 64; i++) {
        h0 = (h0 ^ (h0 >> 17)) * 0xbf58476d1ce4e5b9ULL;
        h0 = (h0 ^ (h0 >> 31)) * 0x94d049bb133111ebULL;
        h0 = h0 ^ (h0 >> 32);
        h1 = (h1 ^ (h1 >> 33)) * 0xff51afd7ed558ccdULL;
        h1 = (h1 ^ (h1 >> 33)) * 0xc4ceb9fe1a85ec53ULL;
        h1 = h1 ^ (h1 >> 33);
        h0 ^= h1; h1 ^= h0;
    }
    memcpy(key,     &h0, 8);
    memcpy(key + 8, &h1, 8);
    // Fill remaining 16 bytes with derived variants
    for (int i = 0; i < 4; i++) {
        uint64_t v = h0 * (i + 3) ^ h1 + 0xdeadbeefcafe0000ULL * (i + 1);
        memcpy(key + 16 + i * 4, &v, 4);
    }
}

// ============================================================
//  XOR stream cipher using derived key + nonce (like ChaCha20)
// ============================================================
static inline void xor_cipher(const uint8_t *key, uint64_t nonce,
                               uint8_t *data, size_t len) {
    uint64_t keystream;
    for (size_t i = 0; i < len; i++) {
        if (i % 8 == 0) {
            uint64_t k;
            memcpy(&k, key + (i / 8) % 32, 8);
            keystream = k ^ (nonce + i / 8);
            // Mix
            keystream ^= keystream >> 33;
            keystream *= 0xff51afd7ed558ccdULL;
            keystream ^= keystream >> 33;
        }
        data[i] ^= ((uint8_t*)&keystream)[i % 8];
    }
}

// ============================================================
//  Pretty-print hex bytes
// ============================================================
static inline void print_hex(const char *label, const uint8_t *data, size_t len) {
    printf("%s%s%s: ", CYAN, label, RESET);
    for (size_t i = 0; i < len; i++) printf("%02x", data[i]);
    printf("\n");
}

// ============================================================
//  Banner printer
// ============================================================
static inline void print_banner(const char *role) {
    printf("\n%s%s", BOLD, MAGENTA);
    printf("╔══════════════════════════════════════════════════╗\n");
    printf("║   Diffie-Hellman Key Exchange — %-16s║\n", role);
    printf("║   Safe Prime p = 576460752303424907               ║\n");
    printf("║   Miller-Rabin Primality Verification            ║\n");
    printf("║   XOR Stream Cipher  +  KDF  Built-in            ║\n");
    printf("╚══════════════════════════════════════════════════╝\n");
    printf("%s\n", RESET);
}

// ============================================================
//  Log helpers
// ============================================================
#include <stdarg.h>

static inline void log_step(int step, const char *fmt, ...) {
    printf("%s[Step %d]%s %s", YELLOW, step, RESET, BOLD);
    va_list ap; va_start(ap, fmt); vprintf(fmt, ap); va_end(ap);
    printf("%s\n", RESET);
}
static inline void log_ok(const char *fmt, ...) {
    printf("  %s✔%s  ", GREEN, RESET);
    va_list ap; va_start(ap, fmt); vprintf(fmt, ap); va_end(ap);
    printf("\n");
}
static inline void log_info(const char *fmt, ...) {
    printf("  %s→%s  ", BLUE, RESET);
    va_list ap; va_start(ap, fmt); vprintf(fmt, ap); va_end(ap);
    printf("\n");
}

#endif // DH_COMMON_H