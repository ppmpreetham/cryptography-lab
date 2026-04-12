#include <stdio.h>
#include <stdint.h>

// stubs (get actual code from lab-4)
uint8_t encrypt(uint8_t pt, uint16_t key);
uint8_t decrypt(uint8_t ct, uint16_t key);

void xorBlocks(uint8_t *out, uint8_t a, uint8_t b) {
    *out = a ^ b;
}

// ecb
void ecb_encrypt(uint8_t *pt, uint8_t *ct, int n, uint16_t key) {
    for (int i = 0; i < n; i++)
        ct[i] = encrypt(pt[i], key);
}

void ecb_decrypt(uint8_t *ct, uint8_t *pt, int n, uint16_t key) {
    for (int i = 0; i < n; i++)
        pt[i] = decrypt(ct[i], key);
}

// cbc
void cbc_encrypt(uint8_t *pt, uint8_t *ct, int n, uint8_t iv, uint16_t key) {
    uint8_t prev = iv;

    for (int i = 0; i < n; i++) {
        uint8_t x;
        xorBlocks(&x, pt[i], prev);
        ct[i] = encrypt(x, key);
        prev = ct[i];
    }
}

void cbc_decrypt(uint8_t *ct, uint8_t *pt, int n, uint8_t iv, uint16_t key) {
    uint8_t prev = iv;

    for (int i = 0; i < n; i++) {
        uint8_t x = decrypt(ct[i], key);
        xorBlocks(&pt[i], x, prev);
        prev = ct[i];
    }
}

// cfb
void cfb_encrypt(uint8_t *pt, uint8_t *ct, int n, uint8_t iv, uint16_t key) {
    uint8_t prev = iv;

    for (int i = 0; i < n; i++) {
        uint8_t k = encrypt(prev, key);
        xorBlocks(&ct[i], pt[i], k);
        prev = ct[i];
    }
}

void cfb_decrypt(uint8_t *ct, uint8_t *pt, int n, uint8_t iv, uint16_t key) {
    uint8_t prev = iv;

    for (int i = 0; i < n; i++) {
        uint8_t k = encrypt(prev, key);
        xorBlocks(&pt[i], ct[i], k);
        prev = ct[i];
    }
}

// ofb
void ofb_crypt(uint8_t *in, uint8_t *out, int n, uint8_t iv, uint16_t key) {
    uint8_t stream = iv;

    for (int i = 0; i < n; i++) {
        stream = encrypt(stream, key);
        xorBlocks(&out[i], in[i], stream);
    }
}

// counter
void ctr_crypt(uint8_t *in, uint8_t *out, int n, uint8_t nonce, uint16_t key) {
    for (int i = 0; i < n; i++) {
        uint8_t counter = nonce + i;
        uint8_t k = encrypt(counter, key);
        xorBlocks(&out[i], in[i], k);
    }
}
