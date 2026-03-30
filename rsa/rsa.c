/**
 * rsa.c – Single source of truth for all RSA logic.
 * Both server and client link this file; no logic is duplicated.
 */
#include "rsa.h"
#include <time.h>

/* ── Status strings (one definition; extern in rsa.h) ─────────────── */
const char *RSA_STATUS_STR[] = {
    "OK",
    "Not a prime number",
    "p and q must be different primes",
    "Key generation failed: gcd(e, phi) != 1 — choose different primes",
    "Message is empty",
    "Message integer >= modulus n  (message too long for these primes)",
    "Message exceeds maximum length",
    "Socket / network error",
    "Protocol parse error",
};

/* ══════════════════════════════════════════════════════════════════════
 *  Math
 * ══════════════════════════════════════════════════════════════════════ */

rsa_uint rsa_powmod(rsa_uint base, rsa_uint exp, rsa_uint mod) {
    rsa_uint result = 1;
    base %= mod;
    while (exp > 0) {
        if (exp & 1) {
#ifdef __SIZEOF_INT128__
            result = (unsigned __int128)result * base % mod;
#else
            rsa_uint r = 0, b = base, e2 = result;
            while (e2) { if (e2 & 1) r = (r + b) % mod; b = (b+b)%mod; e2>>=1; }
            result = r;
#endif
        }
#ifdef __SIZEOF_INT128__
        base = (unsigned __int128)base * base % mod;
#else
        { rsa_uint r=0, b=base, e2=base; r=0; b=base;
          while(e2){if(e2&1)r=(r+b)%mod; b=(b+b)%mod; e2>>=1;} base=r; }
#endif
        exp >>= 1;
    }
    return result;
}

rsa_uint rsa_gcd(rsa_uint a, rsa_uint b) {
    while (b) { rsa_uint t = b; b = a % b; a = t; }
    return a;
}

rsa_uint rsa_mod_inverse(rsa_uint e, rsa_uint phi) {
    long long old_r = (long long)e,  r = (long long)phi;
    long long old_s = 1,             s = 0;
    while (r != 0) {
        long long q = old_r / r, tmp;
        tmp = r;   r   = old_r - q * r;   old_r = tmp;
        tmp = s;   s   = old_s - q * s;   old_s = tmp;
    }
    if (old_s < 0) old_s += (long long)phi;
    return (rsa_uint)old_s;
}

/* ══════════════════════════════════════════════════════════════════════
 *  Primality
 * ══════════════════════════════════════════════════════════════════════ */

int rsa_is_prime(rsa_uint n) {
    if (n < 2)  return 0;
    if (n == 2 || n == 3) return 1;
    if (n % 2 == 0) return 0;

    rsa_uint d = n - 1; int r = 0;
    while (d % 2 == 0) { d >>= 1; r++; }

    static const rsa_uint W[] = {2,3,5,7,11,13,17,19,23,29,31,37};
    static const int NW = (int)(sizeof W / sizeof W[0]);

    for (int i = 0; i < NW; i++) {
        rsa_uint a = W[i];
        if (a >= n) continue;
        rsa_uint x = rsa_powmod(a, d, n);
        if (x == 1 || x == n-1) continue;
        int composite = 1;
        for (int j = 0; j < r-1; j++) {
            x = rsa_powmod(x, 2, n);
            if (x == n-1) { composite = 0; break; }
        }
        if (composite) return 0;
    }
    return 1;
}

RsaStatus rsa_validate_prime(rsa_uint v, const char *name) {
    if (!rsa_is_prime(v)) {
        fprintf(stderr, "[!] %s = %llu is NOT prime\n", name, v);
        return RSA_ERR_PRIME;
    }
    return RSA_OK;
}

/* ══════════════════════════════════════════════════════════════════════
 *  Key construction from user-supplied p and q
 * ══════════════════════════════════════════════════════════════════════ */

RsaStatus rsa_build_keypair(rsa_uint p, rsa_uint q, RsaKeyPair *kp) {
    RSA_TRY(rsa_validate_prime(p, "p"));
    RSA_TRY(rsa_validate_prime(q, "q"));

    if (p == q) {
        fprintf(stderr, "[!] p and q must be different\n");
        return RSA_ERR_PRIMES_EQUAL;
    }

    kp->p = p;
    kp->q = q;
    kp->n = p * q;

    rsa_uint phi = (p - 1) * (q - 1);

    /* Try e = 65537 first, fall back to next valid odd e */
    kp->e = 65537;
    if (rsa_gcd(kp->e, phi) != 1) {
        kp->e = 3;
        while (kp->e < phi && rsa_gcd(kp->e, phi) != 1) kp->e += 2;
    }
    if (rsa_gcd(kp->e, phi) != 1) return RSA_ERR_KEYGEN;

    kp->d = rsa_mod_inverse(kp->e, phi);
    return RSA_OK;
}

/* ══════════════════════════════════════════════════════════════════════
 *  Core RSA
 * ══════════════════════════════════════════════════════════════════════ */

rsa_uint rsa_encrypt(rsa_uint m, rsa_uint e, rsa_uint n) {
    return rsa_powmod(m, e, n);
}

rsa_uint rsa_decrypt(rsa_uint c, rsa_uint d, rsa_uint n) {
    return rsa_powmod(c, d, n);
}

/* ══════════════════════════════════════════════════════════════════════
 *  Message <-> integer  (big-endian, up to 7 bytes so m < 2^56 < n)
 * ══════════════════════════════════════════════════════════════════════ */

/* Maximum characters that can safely be packed into one rsa_uint.
   We use 7 bytes so the integer stays below ~72 quadrillion, comfortably
   within any n formed from two 4-digit-or-larger primes.              */
#define RSA_CHARS_PER_BLOCK 7

RsaStatus rsa_str_to_uint(const char *msg, rsa_uint *out) {
    if (!msg || msg[0] == '\0') return RSA_ERR_MSG_EMPTY;
    *out = 0;
    size_t len = strlen(msg);
    if (len > RSA_CHARS_PER_BLOCK) len = RSA_CHARS_PER_BLOCK;
    for (size_t i = 0; i < len; i++)
        *out = (*out << 8) | (unsigned char)msg[i];
    return RSA_OK;
}

RsaStatus rsa_uint_to_str(rsa_uint v, char *buf, size_t buflen) {
    if (buflen < RSA_CHARS_PER_BLOCK + 1) return RSA_ERR_MSG_TOO_LONG;
    size_t pos = 0;
    for (int i = RSA_CHARS_PER_BLOCK - 1; i >= 0; i--) {
        unsigned char byte = (v >> (8 * i)) & 0xFF;
        if (byte == 0 && pos == 0) continue;
        buf[pos++] = (char)byte;
    }
    buf[pos] = '\0';
    return RSA_OK;
}

/* ══════════════════════════════════════════════════════════════════════
 *  Input validation and prompting
 * ══════════════════════════════════════════════════════════════════════ */

/* Validate that the message fits within the key's modulus n.
   Messages longer than RSA_CHARS_PER_BLOCK are split by the caller;
   here we just check the packed integer fits.                         */
RsaStatus rsa_validate_message(const char *msg, rsa_uint n) {
    if (!msg || msg[0] == '\0') return RSA_ERR_MSG_EMPTY;
    if (strlen(msg) > RSA_MSG_MAX) return RSA_ERR_MSG_TOO_LONG;

    /* Check the first block fits */
    rsa_uint m = 0;
    size_t len = strlen(msg);
    if (len > RSA_CHARS_PER_BLOCK) len = RSA_CHARS_PER_BLOCK;
    for (size_t i = 0; i < len; i++)
        m = (m << 8) | (unsigned char)msg[i];

    if (m >= n) return RSA_ERR_MSG_TOO_LARGE;
    return RSA_OK;
}

/* Prompt for a prime, re-ask until the user enters a valid one. */
rsa_uint rsa_prompt_prime(const char *prompt) {
    char line[64];
    for (;;) {
        printf("%s", prompt);
        fflush(stdout);
        if (!fgets(line, sizeof line, stdin)) continue;
        line[strcspn(line, "\n")] = '\0';
        if (line[0] == '\0') { printf("    [!] Input cannot be empty.\n"); continue; }

        char *end;
        unsigned long long v = strtoull(line, &end, 10);
        if (*end != '\0') { printf("    [!] Enter a whole number.\n"); continue; }
        if (v < 2)         { printf("    [!] Must be >= 2.\n"); continue; }
        if (!rsa_is_prime((rsa_uint)v)) {
            printf("    [!] %llu is NOT prime. Try again.\n", v);
            continue;
        }
        return (rsa_uint)v;
    }
}

/* Prompt for a non-empty string; strips trailing newline. */
void rsa_prompt_string(const char *prompt, char *buf, size_t buflen) {
    for (;;) {
        printf("%s", prompt);
        fflush(stdout);
        if (!fgets(buf, (int)buflen, stdin)) { buf[0] = '\0'; return; }
        buf[strcspn(buf, "\n")] = '\0';
        if (buf[0] != '\0') return;
        printf("    [!] Input cannot be empty. Try again.\n");
    }
}