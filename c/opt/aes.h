/*
 * The AES round on x86 (AES-NI) and ARMv8 (AESE/AESMC), R = MC . SR . SB.
 *
 * The ISAs fuse the round key on opposite sides:
 *   x86  AESENC(x, k)        = R(x) ^ k
 *   ARM  AESMC(AESE(x, k))   = R(x ^ k)
 * so a cipher picks per ISA which XOR rides along. AES_ARM_FORM is set when
 * the ARM shapes are the cheap ones.
 *
 * FAKE_NEON builds the ARM code path on x86, from AES-NI, so the ARM logic
 * can be tested on an x86 machine:
 *   AESE(x, k)  = SR(SB(x ^ k))   = AESENCLAST(x ^ k, 0)
 *   AESMC(x)    = MC(x)           = AESENC(AESDECLAST(x, 0), 0)
 */
#ifndef AES_H
#define AES_H

#include <stdint.h>

#if defined(__aarch64__)
#include <arm_neon.h>

#define AES_ARM_FORM 1
typedef uint8x16_t blk;
#define LD(p) vld1q_u8((const uint8_t *)(p))
#define ST(p, v) vst1q_u8((uint8_t *)(p), (v))
#define XOR(a, b) veorq_u8((a), (b))
#define ZERO() vdupq_n_u8(0)
#define AESE(x, k) vaeseq_u8((x), (k))
#define AESMC(x) vaesmcq_u8(x)
#if defined(__ARM_FEATURE_SHA3)
#define XOR3(a, b, c) veor3q_u8((a), (b), (c))
#else
#define XOR3(a, b, c) XOR(XOR((a), (b)), (c))
#endif
static inline blk set64(uint64_t hi, uint64_t lo) {
    return vreinterpretq_u8_u64(vcombine_u64(vcreate_u64(lo), vcreate_u64(hi)));
}

#elif defined(__x86_64__)
#include <immintrin.h>

typedef __m128i blk;
#define LD(p) _mm_loadu_si128((const blk *)(p))
#define ST(p, v) _mm_storeu_si128((blk *)(p), (v))
#define XOR(a, b) _mm_xor_si128((a), (b))
#define XOR3(a, b, c) XOR(XOR((a), (b)), (c))
#define ZERO() _mm_setzero_si128()
static inline blk set64(uint64_t hi, uint64_t lo) {
    return _mm_set_epi64x((long long)hi, (long long)lo);
}

#if defined(FAKE_NEON)
#define AES_ARM_FORM 1
#define AESE(x, k) _mm_aesenclast_si128(XOR((x), (k)), ZERO())
#define AESMC(x) _mm_aesenc_si128(_mm_aesdeclast_si128((x), ZERO()), ZERO())
#endif

#else
#error "needs x86-64 with AES-NI or AArch64 with the crypto extension"
#endif

#if defined(AES_ARM_FORM)
static inline blk r_in(blk a, blk b) { return AESMC(AESE(a, b)); }             /* R(a ^ b) */
static inline blk r_out(blk a, blk k) { return XOR(AESMC(AESE(a, ZERO())), k); } /* R(a) ^ k */
#else
static inline blk r_in(blk a, blk b) { return _mm_aesenc_si128(XOR(a, b), ZERO()); }
static inline blk r_out(blk a, blk k) { return _mm_aesenc_si128(a, k); }
#endif

#endif
