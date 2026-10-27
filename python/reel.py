"""Reel-256 reference implementation, written from spec/reel.md.

Pure Python, slow, not constant-time. It exists to define the cipher
executably and to generate and check test vectors:

    python3 python/reel.py check test-vectors/reel256.json
    python3 python/reel.py generate > test-vectors/reel256.json
"""

import json
import sys

KEYBYTES, NONCEBYTES, TAGBYTES = 32, 16, 16

# The first 256 bits of the hexadecimal expansion of pi, 3.243F6A88...
C0 = bytes.fromhex("3243f6a8885a308d313198a2e0370734")
C1 = bytes.fromhex("4a4093822299f31d0082efa98ec4e6c8")


def _sbox():
    def mul(a, b):
        r = 0
        while b:
            if b & 1:
                r ^= a
            a = ((a << 1) ^ 0x11B) if a & 0x80 else a << 1
            b >>= 1
        return r

    box = []
    for x in range(256):
        inv = next((y for y in range(1, 256) if mul(x, y) == 1), 0)
        s = inv
        for k in range(1, 5):
            s ^= ((inv << k) | (inv >> (8 - k))) & 0xFF
        box.append(s ^ 0x63)
    return box


SBOX = _sbox()


def _xtime(a):
    return ((a << 1) ^ 0x1B) & 0xFF if a & 0x80 else a << 1


def R(x):
    """One AES round without AddRoundKey: MixColumns(ShiftRows(SubBytes(x))).

    Byte i of the block is row i % 4, column i // 4, as in FIPS 197.
    """
    y = [SBOX[x[4 * ((c + r) % 4) + r]] for c in range(4) for r in range(4)]
    out = bytearray(16)
    for c in range(4):
        a = y[4 * c : 4 * c + 4]
        for r in range(4):
            out[4 * c + r] = (_xtime(a[r]) ^ _xtime(a[(r + 1) % 4]) ^ a[(r + 1) % 4]
                              ^ a[(r + 2) % 4] ^ a[(r + 3) % 4])
    return bytes(out)


def xor(*ws):
    out = bytearray(16)
    for w in ws:
        for i in range(16):
            out[i] ^= w[i]
    return bytes(out)


class State:
    def __init__(self, key, nonce):
        assert len(key) == KEYBYTES and len(nonce) == NONCEBYTES
        k0, k1, n, z = key[:16], key[16:], nonce, bytes(16)
        self.s = [C0, k0, C0, n, z, k0, z, C1, k1, z, xor(n, k1), C0, C1, k1, z, xor(C0, C1)]
        self.diffuse(k0, k1)
        # key feed-forward: the state can no longer be run back to the key
        self.s = [xor(w, k0 if i % 2 == 0 else k1) for i, w in enumerate(self.s)]

    def step(self, m):
        """Absorb one block; return its ciphertext block. Spec section 3.2."""
        s = self.s
        t = xor(R(xor(s[0], s[3])), m)
        c = xor(t, s[8])
        new = xor(t, R(xor(s[12], s[9])))
        s[8] = xor(s[8], m)
        self.s = s[1:] + [new]
        return c

    def keystream(self):
        s = self.s
        return xor(R(xor(s[0], s[3])), s[8])

    def diffuse(self, x0, x1):
        for _ in range(16):
            self.step(x0)
            self.step(x1)

    def finalize(self, ad_len, msg_len):
        lens = (8 * ad_len).to_bytes(8, "little") + (8 * msg_len).to_bytes(8, "little")
        self.diffuse(lens, lens)
        return xor(*self.s)


def _blocks(data):
    for i in range(0, len(data), 16):
        yield data[i : i + 16]


def encrypt(key, nonce, ad, msg):
    st = State(key, nonce)
    for a in _blocks(ad):
        st.step(a.ljust(16, b"\0"))
    ct = b""
    for m in _blocks(msg):
        ct += st.step(m.ljust(16, b"\0"))[: len(m)]
    return ct, st.finalize(len(ad), len(msg))


def decrypt(key, nonce, ad, ct, tag):
    """Plaintext, or None if the tag does not verify."""
    st = State(key, nonce)
    for a in _blocks(ad):
        st.step(a.ljust(16, b"\0"))
    msg = b""
    for c in _blocks(ct):
        r = len(c)
        ks = st.keystream()
        m = xor(c + ks[r:], ks)  # a partial block decrypts to zero padding
        st.step(m)
        msg += m[:r]
    want = st.finalize(len(ad), len(ct))
    if sum(a ^ b for a, b in zip(want, tag)) != 0:
        return None
    return msg


def _pattern(n, seed):
    return bytes((seed * 31 + 7 * i + (i >> 3)) & 0xFF for i in range(n))


CASES = [
    ("empty message, no AD", 0, 0),
    ("empty message, 13-byte AD", 13, 0),
    ("AD only, two blocks", 32, 0),
    ("one byte", 0, 1),
    ("15 bytes", 0, 15),
    ("one block", 0, 16),
    ("one block and one byte, one-block AD", 16, 17),
    ("255 bytes", 0, 255),
    ("256 bytes, the 16-step ring period", 0, 256),
    ("257 bytes, 16-byte AD", 16, 257),
    ("1000 bytes, 13-byte AD", 13, 1000),
    ("1420 bytes, 16-byte AD", 16, 1420),
]


def generate():
    vectors = []
    for i, (name, ad_len, msg_len) in enumerate(CASES):
        key, nonce = _pattern(32, i), _pattern(16, i + 100)
        ad, msg = _pattern(ad_len, i + 200), _pattern(msg_len, i + 300)
        ct, tag = encrypt(key, nonce, ad, msg)
        vectors.append({"name": name, "key": key.hex(), "nonce": nonce.hex(), "ad": ad.hex(),
                        "msg": msg.hex(), "ct": ct.hex(), "tag": tag.hex()})
    return {"algorithm": "Reel-256", "spec": "spec/reel.md, draft-00", "vectors": vectors}


def check(path):
    fails = 0
    for v in json.load(open(path))["vectors"]:
        key, nonce, ad, msg, ct, tag = (bytes.fromhex(v[k]) for k in
                                        ("key", "nonce", "ad", "msg", "ct", "tag"))
        got_ct, got_tag = encrypt(key, nonce, ad, msg)
        ok = got_ct == ct and got_tag == tag and decrypt(key, nonce, ad, ct, tag) == msg
        bad = bytes([tag[0] ^ 1]) + tag[1:]
        ok &= decrypt(key, nonce, ad, ct, bad) is None
        print(("ok    " if ok else "FAIL  ") + v["name"])
        fails += not ok
    print("FAILED" if fails else "all passed")
    return fails


if __name__ == "__main__":
    if sys.argv[1:2] == ["check"] and len(sys.argv) == 3:
        sys.exit(check(sys.argv[2]) != 0)
    elif sys.argv[1:] == ["generate"]:
        print(json.dumps(generate(), indent=2))
    else:
        sys.exit(__doc__)
