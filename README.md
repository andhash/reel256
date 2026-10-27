# Reel-256

Experimental authenticated encryption (AEAD). One AES round, without the key
addition. Two AES rounds per 16-byte block. Draft-00.

> **Experimental. Do not protect real data with Reel.**

| | |
|---|---|
| Key | 32 bytes |
| Nonce | 16 bytes, never repeat a nonce under one key |
| Tag | 16 bytes |
| State | 16 × 16-byte words |

The step, on a ring of sixteen words. `R` is SubBytes, ShiftRows, MixColumns:

```
t    = R(S0 ⊕ S3) ⊕ M
C    = t ⊕ S8
new  = t ⊕ R(S12 ⊕ S9)
S8 ⊕= M, then rotate by one word; new becomes S15
```

Initialization runs 32 steps, then XORs the key into every state word.
Finalization runs 32 steps on the length block. The tag is the XOR of the
sixteen state words. The reference is [`python/reel.py`](python/reel.py).

## Implementations

Four implementations, checked on the same twelve vectors in
[`test-vectors/reel256.json`](test-vectors/reel256.json).

| Path | What it is |
|---|---|
| [`python/reel.py`](python/reel.py) | Reference. Generates the test vectors. |
| [`c/ref/reel_ref.c`](c/ref/reel_ref.c) | Portable C. Not constant-time. |
| [`go/reel.go`](go/reel.go) | Portable Go. Not constant-time. |
| [`c/opt/reel_opt.c`](c/opt/reel_opt.c) | AES-NI and ARMv8. |

The C interface is [`c/include/reel.h`](c/include/reel.h). Link exactly one
of the C files.

```c
void reel256_encrypt(uint8_t *ct, uint8_t tag[16],
                     const uint8_t *msg, size_t msg_len,
                     const uint8_t *ad, size_t ad_len,
                     const uint8_t key[32], const uint8_t nonce[16]);

int reel256_decrypt(uint8_t *msg, const uint8_t *ct, size_t ct_len,
                    const uint8_t tag[16], const uint8_t *ad, size_t ad_len,
                    const uint8_t key[32], const uint8_t nonce[16]);
```

`reel256_decrypt` returns 0 and the plaintext, or −1 with `msg` wiped, when
the tag does not match. `ct` may alias `msg`.

The Go package is `reel`. `Encrypt` returns ciphertext and tag.
`Decrypt` returns the plaintext, or `ErrTag` and no plaintext.

## Build and test

```sh
make test
make bench
```

`make test` needs a C11 compiler, Python 3, and Go 1.22 or later.
`c/opt` needs AES-NI or the ARMv8 crypto extension.

## License

Code, tests, and test vectors are [Apache-2.0](LICENSE).
