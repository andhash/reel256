/*
 * Reel-256 authenticated encryption, draft-00. EXPERIMENTAL: not reviewed,
 * do not protect real data with it. Specification: spec/reel.md.
 *
 * Two implementations share this interface: reel_ref.c (portable C, not
 * constant-time) and reel_opt.c (x86-64 AES-NI or ARMv8 crypto extension).
 * Link exactly one.
 */
#ifndef REEL_H
#define REEL_H

#include <stddef.h>
#include <stdint.h>

#define REEL256_KEYBYTES 32
#define REEL256_NONCEBYTES 16
#define REEL256_TAGBYTES 16

#ifdef __cplusplus
extern "C" {
#endif

/* ct may equal msg; ct receives msg_len bytes. A nonce must never repeat under one key. */
void reel256_encrypt(uint8_t *ct, uint8_t tag[REEL256_TAGBYTES], const uint8_t *msg,
                     size_t msg_len, const uint8_t *ad, size_t ad_len,
                     const uint8_t key[REEL256_KEYBYTES],
                     const uint8_t nonce[REEL256_NONCEBYTES]);

/* 0 and the plaintext on success; -1 and msg zeroed if the tag does not verify. */
int reel256_decrypt(uint8_t *msg, const uint8_t *ct, size_t ct_len,
                    const uint8_t tag[REEL256_TAGBYTES], const uint8_t *ad, size_t ad_len,
                    const uint8_t key[REEL256_KEYBYTES],
                    const uint8_t nonce[REEL256_NONCEBYTES]);

#ifdef __cplusplus
}
#endif

#endif
