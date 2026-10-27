/*
 * Known answers from test-vectors/reel256.json, for whichever implementation
 * this is linked with: encryption, decryption, in-place use, and rejection of
 * a modified ciphertext, tag or AD.
 */
#include <stdio.h>
#include <string.h>

#include "reel.h"
#include "vectors.h"

static size_t unhex(uint8_t *out, const char *hex) {
    size_t n = strlen(hex) / 2;
    for (size_t i = 0; i < n; i++) sscanf(hex + 2 * i, "%2hhx", &out[i]);
    return n;
}

int main(void) {
    int fails = 0;
    for (size_t v = 0; v < sizeof vectors / sizeof *vectors; v++) {
        uint8_t key[32], nonce[16], tag[16], got_tag[16];
        uint8_t ad[64], msg[2048], ct[2048], buf[2048];
        unhex(key, vectors[v].key);
        unhex(nonce, vectors[v].nonce);
        size_t ad_len = unhex(ad, vectors[v].ad);
        size_t len = unhex(msg, vectors[v].msg);
        unhex(ct, vectors[v].ct);
        unhex(tag, vectors[v].tag);

        reel256_encrypt(buf, got_tag, msg, len, ad, ad_len, key, nonce);
        int ok = !memcmp(buf, ct, len) && !memcmp(got_tag, tag, 16);
        ok &= reel256_decrypt(buf, ct, len, tag, ad, ad_len, key, nonce) == 0 &&
              !memcmp(buf, msg, len);

        memcpy(buf, msg, len); /* in place */
        reel256_encrypt(buf, got_tag, buf, len, ad, ad_len, key, nonce);
        ok &= !memcmp(buf, ct, len) && !memcmp(got_tag, tag, 16);
        ok &= reel256_decrypt(buf, buf, len, tag, ad, ad_len, key, nonce) == 0 &&
              !memcmp(buf, msg, len);

        tag[15] ^= 0x80;
        ok &= reel256_decrypt(buf, ct, len, tag, ad, ad_len, key, nonce) == -1;
        tag[15] ^= 0x80;
        if (len) {
            ct[len - 1] ^= 1;
            ok &= reel256_decrypt(buf, ct, len, tag, ad, ad_len, key, nonce) == -1;
            ct[len - 1] ^= 1;
        }
        if (ad_len) {
            ad[0] ^= 1;
            ok &= reel256_decrypt(buf, ct, len, tag, ad, ad_len, key, nonce) == -1;
        }
        printf("%s  %s\n", ok ? "ok  " : "FAIL", vectors[v].name);
        fails += !ok;
    }
    printf("%s\n", fails ? "FAILED" : "all passed");
    return fails != 0;
}
