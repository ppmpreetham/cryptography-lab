/**
 * rsa.h – Shared RSA types, constants, and declarations
 * DRY: every shared symbol lives here exactly once.
 */
#ifndef RSA_H
#define RSA_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ── Configuration ─────────────────────────────────────────────────── */
#define RSA_PORT            9999        /* fixed port, no CLI arg needed  */
#define RSA_MSG_MAX         256         /* max plaintext chars            */
#define RSA_BUF_MAX         1024        /* network buffer                 */

/* Wire protocol: one JSON line per message ----------------------------- */
#define RSA_JSON_KEY_FMT    "{\"e\":%llu,\"n\":%llu}\n"
#define RSA_JSON_CT_FMT     "{\"ciphertext\":%llu}\n"
#define RSA_JSON_ACK_FMT    "{\"status\":\"ok\",\"decrypted\":\"%s\"}\n"
#define RSA_JSON_ERR_FMT    "{\"error\":\"%s\"}\n"

/* ── Portable unsigned type for RSA values ─────────────────────────── */
typedef unsigned long long rsa_uint;

/* ── Key pair ──────────────────────────────────────────────────────── */
typedef struct {
    rsa_uint p;   /* prime p (server keeps this)   */
    rsa_uint q;   /* prime q (server keeps this)   */
    rsa_uint e;   /* public  exponent              */
    rsa_uint d;   /* private exponent              */
    rsa_uint n;   /* modulus  p * q                */
} RsaKeyPair;

/* ── Status codes ──────────────────────────────────────────────────── */
typedef enum {
    RSA_OK = 0,
    RSA_ERR_PRIME,          /* value is not prime                        */
    RSA_ERR_PRIMES_EQUAL,   /* p and q must differ                       */
    RSA_ERR_KEYGEN,         /* e and phi(n) not coprime                  */
    RSA_ERR_MSG_EMPTY,      /* empty message                             */
    RSA_ERR_MSG_TOO_LARGE,  /* message integer >= n                      */
    RSA_ERR_MSG_TOO_LONG,   /* string > RSA_MSG_MAX                      */
    RSA_ERR_SOCKET,         /* socket / network error                    */
    RSA_ERR_PARSE,          /* JSON / protocol parse error               */
} RsaStatus;

/* Defined once in rsa.c */
extern const char *RSA_STATUS_STR[];

/* ── Early-return error macro ──────────────────────────────────────── */
#define RSA_TRY(expr)                                               \
    do {                                                            \
        RsaStatus _s = (expr);                                      \
        if (_s != RSA_OK) {                                         \
            fprintf(stderr, "[!] %s\n", RSA_STATUS_STR[_s]);       \
            return _s;                                              \
        }                                                           \
    } while (0)

/* ── Math ──────────────────────────────────────────────────────────── */
rsa_uint  rsa_powmod(rsa_uint base, rsa_uint exp, rsa_uint mod);
rsa_uint  rsa_gcd(rsa_uint a, rsa_uint b);
rsa_uint  rsa_mod_inverse(rsa_uint e, rsa_uint phi);

/* ── Primality ─────────────────────────────────────────────────────── */
int       rsa_is_prime(rsa_uint n);
RsaStatus rsa_validate_prime(rsa_uint v, const char *name);

/* ── Key construction (user supplies p, q) ─────────────────────────── */
RsaStatus rsa_build_keypair(rsa_uint p, rsa_uint q, RsaKeyPair *kp);

/* ── Core RSA ──────────────────────────────────────────────────────── */
rsa_uint  rsa_encrypt(rsa_uint m, rsa_uint e, rsa_uint n);
rsa_uint  rsa_decrypt(rsa_uint c, rsa_uint d, rsa_uint n);

/* ── Message <-> integer (up to 7 ASCII chars to stay < 64-bit max) ── */
RsaStatus rsa_str_to_uint(const char *msg, rsa_uint *out);
RsaStatus rsa_uint_to_str(rsa_uint v, char *buf, size_t buflen);

/* ── Input helpers ─────────────────────────────────────────────────── */
RsaStatus rsa_validate_message(const char *msg, rsa_uint n);
rsa_uint  rsa_prompt_prime(const char *prompt);
void      rsa_prompt_string(const char *prompt, char *buf, size_t buflen);

#endif /* RSA_H */