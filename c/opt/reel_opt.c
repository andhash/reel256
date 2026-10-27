/*
 * Reel-256 on x86-64 AES-NI and the ARMv8 crypto extension.
 *
 * The step (spec/reel.md, 3.2), all reads from the state before the step:
 *   t    = R(S0 ^ S3) ^ M
 *   C    = t ^ S8
 *   new  = t ^ R(S12 ^ S9)
 *   S8 ^= M, then rotate: S0..S15 <- S1..S15, new
 *
 * The rotation is never executed. The state is a ring and `off` indexes the
 * logical S0; a step writes `new` into slot off, which is the logical S15
 * once off advances. Between calls the ring is kept rotated so that off is 0.
 * Inside blocks(), sixteen unrolled steps with constant indices keep the
 * state in registers.
 *
 * Constant-time on cores whose AES instructions are (all AES-NI and ARMv8
 * crypto cores known to us); tag comparison is constant-time. Not reviewed
 * beyond that.
 */
#include <string.h>

#include "aes.h"
#include "reel.h"

#define S(i) s[(off + (i)) & 15]

static inline blk step(blk *s, unsigned off, blk m) {
#if defined(AES_ARM_FORM)
    /* AESE+AESMC gives R(a ^ b); EOR3 folds t into both uses */
    blk a = r_in(S(0), S(3)), b = r_in(S(12), S(9));
    blk c = XOR3(a, m, S(8));
    S(0) = XOR3(a, m, b);
#else
    /* AESENC(x, k) gives R(x) ^ k */
    blk t = r_out(XOR(S(0), S(3)), m);
    blk c = XOR(t, S(8));
    S(0) = r_out(XOR(S(12), S(9)), t);
#endif
    S(8) = XOR(S(8), m);
    return c;
}

static inline blk keystream_at(const blk *s, unsigned off) {
    return XOR(r_in(S(0), S(3)), S(8));
}

/* The same state change as step(), recovering M from C: t = C ^ S8 */
static inline blk step_dec(blk *s, unsigned off, blk c) {
#if defined(AES_ARM_FORM)
    blk m = XOR3(r_in(S(0), S(3)), c, S(8));
    S(0) = XOR3(c, S(8), r_in(S(12), S(9)));
#else
    blk t = XOR(c, S(8));
    blk m = r_out(XOR(S(0), S(3)), t);
    S(0) = r_out(XOR(S(12), S(9)), t);
#endif
    S(8) = XOR(S(8), m);
    return m;
}

static const uint8_t C0[16] = {0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
                               0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34};
static const uint8_t C1[16] = {0x4a, 0x40, 0x93, 0x82, 0x22, 0x99, 0xf3, 0x1d,
                               0x00, 0x82, 0xef, 0xa9, 0x8e, 0xc4, 0xe6, 0xc8};

/* 32 steps from slot 0, which return to slot 0 */
static void diffuse(blk *s, blk x0, blk x1) {
    blk v[16];
    memcpy(v, s, sizeof v);
#pragma GCC unroll 32
    for (unsigned off = 0; off < 32; off += 2) {
        step(v, off, x0);
        step(v, off + 1, x1);
    }
    memcpy(s, v, sizeof v);
}

static void init(blk *s, const uint8_t key[32], const uint8_t nonce[16]) {
    blk k0 = LD(key), k1 = LD(key + 16), n = LD(nonce);
    blk c0 = LD(C0), c1 = LD(C1), z = ZERO();
    blk v[16] = {c0, k0, c0, n, z, k0, z, c1, k1, z, XOR(n, k1), c0, c1, k1, z, XOR(c0, c1)};
    memcpy(s, v, sizeof v);
    diffuse(s, k0, k1);
    /* key feed-forward: the state can no longer be run back to the key */
    for (int i = 0; i < 16; i++) s[i] = XOR(s[i], i % 2 ? k1 : k0);
}

enum mode { ABSORB, ENC, DEC };

/* n full blocks, the logical S0 in s[0] before and after */
static inline __attribute__((always_inline)) void blocks(blk *s, enum mode mode,
                                                          const uint8_t *in, uint8_t *out,
                                                          size_t n) {
    blk v[16];
    memcpy(v, s, sizeof v);
    size_t i = 0;
#define ONE(j)                                                                    \
    do {                                                                          \
        blk x = LD(in + 16 * (i + (j)));                                          \
        if (mode == DEC)                                                          \
            ST(out + 16 * (i + (j)), step_dec(v, (j), x));                        \
        else if (mode == ENC)                                                     \
            ST(out + 16 * (i + (j)), step(v, (j), x));                            \
        else                                                                      \
            step(v, (j), x);                                                      \
    } while (0)
    for (; i + 16 <= n; i += 16) {
#pragma GCC unroll 16
        for (unsigned j = 0; j < 16; j++) ONE(j);
    }
    size_t r = n - i;
#pragma GCC unroll 16
    for (unsigned j = 0; j < 16; j++)
        if (j < r) ONE(j);
#undef ONE
    for (unsigned k = 0; k < 16; k++) s[k] = v[(k + r) & 15];
}

static void finalize(blk *s, size_t ad_len, size_t msg_len, uint8_t tag[16]) {
    uint8_t lens[16];
    uint64_t a = (uint64_t)ad_len * 8, m = (uint64_t)msg_len * 8;
    for (int i = 0; i < 8; i++) {
        lens[i] = (uint8_t)(a >> (8 * i));
        lens[8 + i] = (uint8_t)(m >> (8 * i));
    }
    blk t = LD(lens);
    diffuse(s, t, t);
    blk acc = s[0];
    for (int i = 1; i < 16; i++) acc = XOR(acc, s[i]);
    ST(tag, acc);
}

static void absorb_ad(blk *s, const uint8_t *ad, size_t len) {
    blocks(s, ABSORB, ad, NULL, len / 16);
    if (len % 16) {
        uint8_t pad[16] = {0};
        memcpy(pad, ad + len / 16 * 16, len % 16);
        blocks(s, ABSORB, pad, NULL, 1);
    }
}

void reel256_encrypt(uint8_t *ct, uint8_t tag[16], const uint8_t *msg, size_t msg_len,
                     const uint8_t *ad, size_t ad_len, const uint8_t key[32],
                     const uint8_t nonce[16]) {
    blk s[16];
    init(s, key, nonce);
    absorb_ad(s, ad, ad_len);
    size_t full = msg_len / 16 * 16, r = msg_len - full;
    blocks(s, ENC, msg, ct, msg_len / 16);
    if (r) {
        uint8_t pad[16] = {0}, out[16];
        memcpy(pad, msg + full, r);
        blocks(s, ENC, pad, out, 1);
        memcpy(ct + full, out, r);
    }
    finalize(s, ad_len, msg_len, tag);
}

int reel256_decrypt(uint8_t *msg, const uint8_t *ct, size_t ct_len, const uint8_t tag[16],
                    const uint8_t *ad, size_t ad_len, const uint8_t key[32],
                    const uint8_t nonce[16]) {
    blk s[16];
    init(s, key, nonce);
    absorb_ad(s, ad, ad_len);
    size_t full = ct_len / 16 * 16, r = ct_len - full;
    blocks(s, DEC, ct, msg, ct_len / 16);
    if (r) {
        /* pad with keystream, so the partial block decrypts to zero padding */
        uint8_t in[16], ks[16], out[16];
        ST(ks, keystream_at(s, 0));
        memcpy(in, ct + full, r);
        memcpy(in + r, ks + r, 16 - r);
        blocks(s, DEC, in, out, 1);
        memcpy(msg + full, out, r);
    }
    uint8_t want[16], diff = 0;
    finalize(s, ad_len, ct_len, want);
    for (int k = 0; k < 16; k++) diff |= want[k] ^ tag[k];
    if (diff) {
        memset(msg, 0, ct_len);
        return -1;
    }
    return 0;
}
