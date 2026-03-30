#ifndef COMMON_H
#define COMMON_H
#include <stdio.h>

#define PRIME         2083
#define MAX_SHARES    10
#define MAX_THRESHOLD 10
#define SOCKET_PATH   "/tmp/shamir_server.sock"

typedef enum {
    MSG_SHARE         = 1, 
    MSG_SHARE_REQUEST = 2, 
    MSG_SHARE_REPLY   = 3, 
    MSG_RESULT        = 4, 
} MsgType;

typedef struct {
    MsgType type;
    int     client_id;
    int     x;
    int     y;
    int     secret;  
} Message;

static long mod_pow(long base, long exp, long p) {
    long r = 1;
    base %= p;
    for (; exp > 0; exp >>= 1) {
        if (exp & 1) r = r * base % p;
        base = base * base % p;
    }
    return r;
}

static long mod_inv(long a, long p) {
    return mod_pow(((a % p) + p) % p, p - 2, p);
}

static int poly_eval(const int *coeffs, int degree, int x, int p) {
    long result = 0, xpow = 1;
    for (int i = 0; i <= degree; i++) {
        result = (result + (long)coeffs[i] * xpow) % p;
        xpow   = xpow * x % p;
    }
    return (int)((result + p) % p);
}

static void warn_duplicate_coeffs(const int *coeffs, int k) {
    for (int i = 0; i < k; i++)
        for (int j = i + 1; j < k; j++)
            if (coeffs[i] == coeffs[j])
                fprintf(stderr,
                    "[WARNING] Duplicate coefficient %d at indices %d and %d.\n"
                    "          The polynomial's effective degree is reduced —\n"
                    "          Shamir's security guarantee is weakened.\n"
                    "          Continuing anyway as requested.\n\n",
                    coeffs[i], i, j);
}

static int lagrange_reconstruct(const int *xs, const int *ys, int k) {
    long secret = 0;
    for (int i = 0; i < k; i++) {
        long num = 1, den = 1;
        for (int j = 0; j < k; j++) {
            if (i == j) continue;
            num = num * ((PRIME - xs[j]) % PRIME) % PRIME;
            den = den * ((xs[i] - xs[j] + PRIME) % PRIME) % PRIME;
        }
        long li = (long)ys[i] % PRIME * num % PRIME * mod_inv(den, PRIME) % PRIME;
        secret  = (secret + li) % PRIME;
    }
    return (int)((secret + PRIME) % PRIME);
}

#endif