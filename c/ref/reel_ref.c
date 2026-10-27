/*
 * Reel-256, portable reference: a direct transcription of spec/reel.md.
 *
 * Readable, slow, and NOT constant-time: the S-box is a table lookup, which
 * leaks through the cache. Use it to understand and to cross-check, not to
 * protect anything.
 */
#include <string.h>

#include "reel.h"

typedef struct {
    uint8_t s[16][16];
} state;

static const uint8_t C0[16] = {0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
                               0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34};
static const uint8_t C1[16] = {0x4a, 0x40, 0x93, 0x82, 0x22, 0x99, 0xf3, 0x1d,
                               0x00, 0x82, 0xef, 0xa9, 0x8e, 0xc4, 0xe6, 0xc8};

static const uint8_t SBOX[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
};

static uint8_t xtime(uint8_t a) { return (uint8_t)((a << 1) ^ ((a >> 7) * 0x1b)); }

/* R(x) = MixColumns(ShiftRows(SubBytes(x))); byte i is row i % 4, column i / 4 */
static void aes_round(uint8_t out[16], const uint8_t x[16]) {
    uint8_t y[16];
    for (int c = 0; c < 4; c++)
        for (int r = 0; r < 4; r++) y[4 * c + r] = SBOX[x[4 * ((c + r) % 4) + r]];
    for (int c = 0; c < 4; c++) {
        const uint8_t *a = y + 4 * c;
        for (int r = 0; r < 4; r++)
            out[4 * c + r] = xtime(a[r]) ^ xtime(a[(r + 1) % 4]) ^ a[(r + 1) % 4] ^
                             a[(r + 2) % 4] ^ a[(r + 3) % 4];
    }
}

static void xor_into(uint8_t *dst, const uint8_t *a, const uint8_t *b) {
    for (int i = 0; i < 16; i++) dst[i] = a[i] ^ b[i];
}

/* Spec 3.2: absorb m, return the ciphertext block in c (may be NULL). */
static void step(state *st, const uint8_t m[16], uint8_t *c) {
    uint8_t (*s)[16] = st->s;
    uint8_t a[16], t[16], b[16], next[16];
    xor_into(a, s[0], s[3]);
    aes_round(t, a);
    xor_into(t, t, m); /* t = R(S0 ^ S3) ^ M */
    if (c) xor_into(c, t, s[8]);
    xor_into(a, s[12], s[9]);
    aes_round(b, a);
    xor_into(next, t, b); /* new = t ^ R(S12 ^ S9) */
    xor_into(s[8], s[8], m);
    memmove(s[0], s[1], 15 * 16);
    memcpy(s[15], next, 16);
}

static void keystream(const state *st, uint8_t ks[16]) {
    uint8_t a[16];
    xor_into(a, st->s[0], st->s[3]);
    aes_round(ks, a);
    xor_into(ks, ks, st->s[8]);
}

static void diffuse(state *st, const uint8_t x0[16], const uint8_t x1[16]) {
    for (int i = 0; i < 16; i++) {
        step(st, x0, NULL);
        step(st, x1, NULL);
    }
}

static void init(state *st, const uint8_t key[32], const uint8_t nonce[16]) {
    static const uint8_t Z[16] = {0};
    const uint8_t *k0 = key, *k1 = key + 16;
    const uint8_t *layout[16] = {C0, k0, C0, nonce, Z, k0, Z, C1, k1, Z, NULL, C0, C1, k1, Z, NULL};
    for (int i = 0; i < 16; i++)
        if (layout[i]) memcpy(st->s[i], layout[i], 16);
    xor_into(st->s[10], nonce, k1);
    xor_into(st->s[15], C0, C1);
    diffuse(st, k0, k1);
    /* key feed-forward: the state can no longer be run back to the key */
    for (int i = 0; i < 16; i++) xor_into(st->s[i], st->s[i], i % 2 ? k1 : k0);
}

static void absorb_ad(state *st, const uint8_t *ad, size_t len) {
    for (size_t i = 0; i < len; i += 16) {
        uint8_t blk[16] = {0};
        memcpy(blk, ad + i, len - i < 16 ? len - i : 16);
        step(st, blk, NULL);
    }
}

static void finalize(state *st, size_t ad_len, size_t msg_len, uint8_t tag[16]) {
    uint8_t lens[16];
    uint64_t a = (uint64_t)ad_len * 8, m = (uint64_t)msg_len * 8;
    for (int i = 0; i < 8; i++) {
        lens[i] = (uint8_t)(a >> (8 * i));
        lens[8 + i] = (uint8_t)(m >> (8 * i));
    }
    diffuse(st, lens, lens);
    memset(tag, 0, 16);
    for (int i = 0; i < 16; i++) xor_into(tag, tag, st->s[i]);
}

void reel256_encrypt(uint8_t *ct, uint8_t tag[16], const uint8_t *msg, size_t msg_len,
                     const uint8_t *ad, size_t ad_len, const uint8_t key[32],
                     const uint8_t nonce[16]) {
    state st;
    init(&st, key, nonce);
    absorb_ad(&st, ad, ad_len);
    for (size_t i = 0; i < msg_len; i += 16) {
        size_t r = msg_len - i < 16 ? msg_len - i : 16;
        uint8_t m[16] = {0}, c[16];
        memcpy(m, msg + i, r);
        step(&st, m, c);
        memcpy(ct + i, c, r);
    }
    finalize(&st, ad_len, msg_len, tag);
}

int reel256_decrypt(uint8_t *msg, const uint8_t *ct, size_t ct_len, const uint8_t tag[16],
                    const uint8_t *ad, size_t ad_len, const uint8_t key[32],
                    const uint8_t nonce[16]) {
    state st;
    init(&st, key, nonce);
    absorb_ad(&st, ad, ad_len);
    for (size_t i = 0; i < ct_len; i += 16) {
        size_t r = ct_len - i < 16 ? ct_len - i : 16;
        uint8_t ks[16], m[16];
        keystream(&st, ks);
        /* a partial block takes keystream bytes as padding, so it decrypts to zeros */
        for (int j = 0; j < 16; j++) m[j] = ((size_t)j < r ? ct[i + j] : ks[j]) ^ ks[j];
        step(&st, m, NULL);
        memcpy(msg + i, m, r);
    }
    uint8_t want[16], diff = 0;
    finalize(&st, ad_len, ct_len, want);
    for (int i = 0; i < 16; i++) diff |= want[i] ^ tag[i];
    if (diff) {
        memset(msg, 0, ct_len);
        return -1;
    }
    return 0;
}
