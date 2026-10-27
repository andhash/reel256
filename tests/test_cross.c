/*
 * The optimized implementation against the reference on every message length
 * from 0 to 1100 bytes and several AD lengths, random contents. Catches
 * partial-block and ring-rotation bugs that fixed vectors can miss.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "reel.h"

void reel256_ref_encrypt(uint8_t *, uint8_t[16], const uint8_t *, size_t, const uint8_t *,
                         size_t, const uint8_t[32], const uint8_t[16]);

static uint64_t rng = 0x9e3779b97f4a7c15u;

static void fill(uint8_t *p, size_t n) {
    for (size_t i = 0; i < n; i++) {
        rng ^= rng << 13, rng ^= rng >> 7, rng ^= rng << 17;
        p[i] = (uint8_t)rng;
    }
}

int main(void) {
    static const size_t ad_lens[] = {0, 1, 15, 16, 17, 255, 256, 257};
    uint8_t key[32], nonce[16], ad[257], msg[1100], a[1100], b[1100], back[1100], ta[16], tb[16];
    long cases = 0, fails = 0;
    for (size_t al = 0; al < sizeof ad_lens / sizeof *ad_lens; al++)
        for (size_t len = 0; len <= sizeof msg; len++) {
            fill(key, 32), fill(nonce, 16), fill(ad, ad_lens[al]), fill(msg, len);
            reel256_encrypt(a, ta, msg, len, ad, ad_lens[al], key, nonce);
            reel256_ref_encrypt(b, tb, msg, len, ad, ad_lens[al], key, nonce);
            int ok = !memcmp(a, b, len) && !memcmp(ta, tb, 16);
            ok &= reel256_decrypt(back, a, len, ta, ad, ad_lens[al], key, nonce) == 0 &&
                  !memcmp(back, msg, len);
            if (!ok && fails++ < 5) printf("FAIL  ad %zu, msg %zu\n", ad_lens[al], len);
            cases++;
        }
    printf("%ld cases, %s\n", cases, fails ? "FAILED" : "all passed");
    return fails != 0;
}
