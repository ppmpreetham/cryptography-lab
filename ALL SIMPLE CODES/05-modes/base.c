#include <stdio.h>
#include <stdint.h>

// stubs (for lab fat)
uint8_t encrypt(uint8_t pt, uint16_t key){
    return pt ^ (uint8_t)key;
}

uint8_t decrypt(uint8_t ct, uint16_t key){
    return ct ^ (uint8_t)key;
}

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

// ofb (same for enc and dec)
void ofb_crypt(uint8_t *in, uint8_t *out, int n, uint8_t iv, uint16_t key) {
    uint8_t stream = iv;

    for (int i = 0; i < n; i++) {
        stream = encrypt(stream, key);
        xorBlocks(&out[i], in[i], stream);
    }
}

// counter (same for enc and dec)
void ctr_crypt(uint8_t *in, uint8_t *out, int n, uint8_t nonce, uint16_t key) {
    for (int i = 0; i < n; i++) {
        uint8_t counter = nonce + i;
        uint8_t k = encrypt(counter, key);
        xorBlocks(&out[i], in[i], k);
    }
}

int pkcs7_pad(uint8_t *in, int len, int block_size, uint8_t *out) {
    int pad = block_size - (len % block_size);
    int new_len = len + pad;

    for (int i = 0; i < len; i++)
        out[i] = in[i];

    for (int i = len; i < new_len; i++)
        out[i] = pad;

    return new_len;
}

int pkcs7_unpad(uint8_t *in, int len) {
    int pad = in[len - 1];

    if (pad <= 0 || pad > len)
        return -1;

    for (int i = len - pad; i < len; i++) {
        if (in[i] != pad)
            return -1;
    }

    return len - pad;
}

void print_arr(char *label, uint8_t *arr, int n) {
    printf("%s: ", label);
    for (int i = 0; i < n; i++)
        printf("%c ", arr[i]);
    printf("\n");
}

int main() {
    uint8_t pt[] = "HELLO";
    uint8_t padded[32];
    uint8_t ct[32];
    uint8_t out[32];

    int block = 8;
    int n = 5;

    uint16_t key = 5;
    uint8_t iv = 10;
    uint8_t nonce = 20;
    int new_len = pkcs7_pad(pt, n, block, padded);
    
    ecb_encrypt(pt, ct, new_len, key);
    ecb_decrypt(ct, out, new_len, key);
    print_arr("ECB Decrypted", out, new_len);

    cbc_encrypt(pt, ct, new_len, iv, key);
    cbc_decrypt(ct, out, new_len, iv, key);
    print_arr("CBC Decrypted", out, new_len);

    cfb_encrypt(pt, ct, new_len, iv, key);
    cfb_decrypt(ct, out, new_len, iv, key);
    print_arr("CFB Decrypted", out, new_len);

    ofb_crypt(pt, ct, new_len, iv, key);
    ofb_crypt(ct, out, new_len, iv, key);
    print_arr("OFB Decrypted", out, new_len);

    ctr_crypt(pt, ct, new_len, nonce, key);
    ctr_crypt(ct, out, new_len, nonce, key);
    print_arr("CTR Decrypted", out, new_len);

    return 0;
}