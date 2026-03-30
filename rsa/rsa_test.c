/**
 * rsa_test.c – Unit tests for rsa.c
 * Run via: make test
 */
#include "rsa.h"

static int tests_run = 0, tests_failed = 0;

#define TEST(name, expr)                                        \
    do {                                                        \
        tests_run++;                                            \
        if (!(expr)) {                                          \
            fprintf(stderr, "  FAIL  %s  (line %d)\n",         \
                    name, __LINE__);                            \
            tests_failed++;                                     \
        } else {                                                \
            printf("  pass  %s\n", name);                       \
        }                                                       \
    } while (0)

static void test_powmod(void) {
    TEST("powmod 2^10 mod 1000 = 24",  rsa_powmod(2, 10, 1000) == 24);
    TEST("powmod 3^0  mod 7   = 1",    rsa_powmod(3,  0,    7) == 1);
    TEST("powmod 5^3  mod 13  = 8",    rsa_powmod(5,  3,   13) == 8);
}

static void test_gcd(void) {
    TEST("gcd(12,8)=4",    rsa_gcd(12, 8)   == 4);
    TEST("gcd(7,13)=1",    rsa_gcd(7,  13)  == 1);
    TEST("gcd(100,75)=25", rsa_gcd(100, 75) == 25);
}

static void test_mod_inverse(void) {
    TEST("mod_inv(3,10)=7",           rsa_mod_inverse(3, 10) == 7);
    TEST("mod_inv(17,3120)*17%3120=1",(rsa_mod_inverse(17,3120)*17)%3120==1);
}

static void test_is_prime(void) {
    TEST("prime  2",      rsa_is_prime(2));
    TEST("prime  7919",   rsa_is_prime(7919));
    TEST("prime  65537",  rsa_is_prime(65537));
    TEST("prime  509",    rsa_is_prime(509));
    TEST("!prime 1",      !rsa_is_prime(1));
    TEST("!prime 4",      !rsa_is_prime(4));
    TEST("!prime 100",    !rsa_is_prime(100));
    TEST("!prime 65536",  !rsa_is_prime(65536));
}

static void test_validate_prime(void) {
    TEST("validate_prime(7)  = OK",  rsa_validate_prime(7, "p") == RSA_OK);
    TEST("validate_prime(9)  = ERR", rsa_validate_prime(9, "p") == RSA_ERR_PRIME);
}

static void test_build_keypair(void) {
    RsaKeyPair kp;
    /* Classic textbook example: p=61, q=53 */
    TEST("build p=61,q=53 OK",    rsa_build_keypair(61, 53, &kp) == RSA_OK);
    TEST("n=3233",                 kp.n == 3233);
    TEST("gcd(e,phi)=1",          rsa_gcd(kp.e, (61-1)*(53-1)) == 1);

    /* Same prime -> ERR */
    TEST("build p=q -> ERR",
         rsa_build_keypair(61, 61, &kp) == RSA_ERR_PRIMES_EQUAL);

    /* Non-prime -> ERR */
    TEST("build p=4 -> ERR",
         rsa_build_keypair(4, 53, &kp) == RSA_ERR_PRIME);
}

static void test_encrypt_decrypt(void) {
    /* p=61 q=53 n=3233 e=17 d=2753  (standard textbook) */
    rsa_uint e=17, d=2753, n=3233, m=65;
    rsa_uint c = rsa_encrypt(m, e, n);
    rsa_uint r = rsa_decrypt(c, d, n);
    TEST("encrypt/decrypt m=65",  r == m);
    TEST("ciphertext != plain",   c != m);
}

static void test_keygen_roundtrip(void) {
    RsaKeyPair kp;
    rsa_build_keypair(509, 757, &kp);
    rsa_uint m = 999;
    TEST("roundtrip p=509,q=757 m=999",
         rsa_decrypt(rsa_encrypt(m, kp.e, kp.n), kp.d, kp.n) == m);
}

static void test_str_roundtrip(void) {
    const char *msg = "Hi!";
    rsa_uint v;
    TEST("str_to_uint OK",  rsa_str_to_uint(msg, &v) == RSA_OK);
    char out[16];
    TEST("uint_to_str OK",  rsa_uint_to_str(v, out, sizeof out) == RSA_OK);
    TEST("str round-trip",  strcmp(out, msg) == 0);
}

static void test_validate_message(void) {
    /* p=509 q=757 -> n=385313, big enough for short strings */
    TEST("empty  -> ERR", rsa_validate_message("",    385313) == RSA_ERR_MSG_EMPTY);
    TEST("NULL   -> ERR", rsa_validate_message(NULL,  385313) == RSA_ERR_MSG_EMPTY);
    TEST("'Hi'   -> OK",  rsa_validate_message("Hi",  385313) == RSA_OK);
    /* 'AAAAAAA' packed = 0x41414141414141 = 18411139887210497 > small n */
    TEST("too large -> ERR", rsa_validate_message("AAAAAAA", 100) == RSA_ERR_MSG_TOO_LARGE);
}

int main(void) {
    printf("=== RSA unit tests ===\n\n");
    test_powmod();
    test_gcd();
    test_mod_inverse();
    test_is_prime();
    test_validate_prime();
    test_build_keypair();
    test_encrypt_decrypt();
    test_keygen_roundtrip();
    test_str_roundtrip();
    test_validate_message();
    printf("\n%d/%d tests passed\n", tests_run - tests_failed, tests_run);
    return tests_failed ? EXIT_FAILURE : EXIT_SUCCESS;
}