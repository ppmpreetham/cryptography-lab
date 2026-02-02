#include <stdio.h>
#include <stdint.h>

// 1 -> n any order
int P10[] = {3,5,2,7,4,10,1,9,8,6};
int P8[]  = {6,3,7,4,8,5,10,9};
int IP[]  = {2,6,3,1,4,8,5,7};
int IP_INV[] = {4,1,3,5,7,2,8,6};
int EP[]  = {4,1,2,3,2,3,4,1};
int P4[]  = {2,4,3,1};

int S0[4][4] = {
    {1,0,3,2},
    {3,2,1,0},
    {0,2,1,3},
    {3,1,3,2}
};

int S1[4][4] = {
    {0,1,2,3},
    {2,0,1,3},
    {3,0,1,0},
    {2,1,0,3}
};

void toBits(uint16_t in, int bits[], int n) {
    for (int i = n - 1; i >= 0; i--) {
        bits[i] = in % 2;
        in /= 2;
    }
}

uint16_t fromBits(int bits[], int n) {
    uint16_t out = 0;
    for (int i = 0; i < n; i++) out = out * 2 + bits[i];
    return out;
}

uint16_t permute(uint16_t in, int P[], int outBits, int inBits) {
    int src[16], dst[16];
    toBits(in, src, inBits);
    for (int i = 0; i < outBits; i++) dst[i] = src[P[i] - 1];
    return fromBits(dst, outBits);
}

uint8_t sbox(uint8_t input, int box[4][4]) {
    int bits[4];

    toBits(input, bits, 4);

    int row = bits[0] * 2 + bits[3];  // b1 b4
    int col = bits[1] * 2 + bits[2];  // b2 b3

    return box[row][col];
}

uint8_t leftShift(uint8_t val, int shifts, int bits) {
    return ((val << shifts) | (val >> (bits - shifts))) & ((1 << bits) - 1);
}

void generateKeys(uint16_t key, uint8_t *K1, uint8_t *K2) {
    uint16_t p10 = permute(key, P10, 10, 10);

    uint8_t left  = p10 >> 5;
    uint8_t right = p10 & 0x1F;

    left  = leftShift(left, 1, 5);
    right = leftShift(right, 1, 5);
    *K1 = permute((left << 5) | right, P8, 8, 10);

    left  = leftShift(left, 2, 5);
    right = leftShift(right, 2, 5);
    *K2 = permute((left << 5) | right, P8, 8, 10);
}

uint8_t F(uint8_t R, uint8_t K) {
    uint8_t ep = permute(R, EP, 8, 4);
    ep ^= K;

    uint8_t left  = ep >> 4;
    uint8_t right = ep & 0xF;

    uint8_t s0 = sbox(left, S0);
    uint8_t s1 = sbox(right, S1);

    uint8_t out = (s0 << 2) | s1;
    return permute(out, P4, 4, 4);
}

uint8_t fk(uint8_t input, uint8_t K) {
    uint8_t L = input >> 4;
    uint8_t R = input & 0xF;

    uint8_t newL = L ^ F(R, K);
    return (newL << 4) | R;
}

uint8_t swap(uint8_t val) {
    return ((val & 0xF) << 4) | (val >> 4);
}

uint8_t sdes(uint8_t plaintext, uint8_t K1, uint8_t K2, int encrypt) {
    uint8_t ip = permute(plaintext, IP, 8, 8);

    if (encrypt) {
        ip = fk(ip, K1);
        ip = swap(ip);
        ip = fk(ip, K2);
    } else {
        ip = fk(ip, K2);
        ip = swap(ip);
        ip = fk(ip, K1);
    }

    return permute(ip, IP_INV, 8, 8);
}