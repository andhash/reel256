// Reel-256, portable reference: a direct transcription of spec/reel.md.
//
// Readable, slow, and not constant-time: the S-box is a table lookup.
// Use it to understand and to cross-check, not to protect anything.
package reel

import (
	"bytes"
	"errors"
)

const (
	KeyBytes   = 32
	NonceBytes = 16
	TagBytes   = 16
)

var (
	ErrKeySize   = errors.New("reel: key must be 32 bytes")
	ErrNonceSize = errors.New("reel: nonce must be 16 bytes")
	ErrTagSize   = errors.New("reel: tag must be 16 bytes")
	ErrTag       = errors.New("reel: tag mismatch")
)

// First 256 bits of the hexadecimal expansion of pi, as in the specification.
var (
	c0 = [16]byte{0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34}
	c1 = [16]byte{0x4a, 0x40, 0x93, 0x82, 0x22, 0x99, 0xf3, 0x1d, 0x00, 0x82, 0xef, 0xa9, 0x8e, 0xc4, 0xe6, 0xc8}
)

// AES S-box. Built the same way as python/reel.py; init checks the first bytes.
var sbox [256]byte

func init() {
	buildSBox()
	if sbox[0] != 0x63 || sbox[1] != 0x7c || sbox[255] != 0x16 {
		panic("reel: S-box is not the AES S-box")
	}
}

func gfMul(a, b int) int {
	r := 0
	for b != 0 {
		if b&1 != 0 {
			r ^= a
		}
		if a&0x80 != 0 {
			a = (a << 1) ^ 0x11b
		} else {
			a <<= 1
		}
		b >>= 1
	}
	return r
}

func buildSBox() {
	for x := 0; x < 256; x++ {
		inv := 0
		if x != 0 {
			for y := 1; y < 256; y++ {
				if gfMul(x, y) == 1 {
					inv = y
					break
				}
			}
		}
		s := inv
		for k := 1; k <= 4; k++ {
			s ^= ((inv << k) | (inv >> (8 - k))) & 0xff
		}
		sbox[x] = byte(s ^ 0x63)
	}
}

func xtime(a byte) byte { return (a << 1) ^ ((a >> 7) * 0x1b) }

func xor16(a, b [16]byte) [16]byte {
	var o [16]byte
	for i := range o {
		o[i] = a[i] ^ b[i]
	}
	return o
}

// R = MixColumns(ShiftRows(SubBytes(x))). Byte i is row i%4, column i/4.
func aesRound(x [16]byte) [16]byte {
	var y, out [16]byte
	for c := 0; c < 4; c++ {
		for r := 0; r < 4; r++ {
			y[4*c+r] = sbox[x[4*((c+r)%4)+r]]
		}
	}
	for c := 0; c < 4; c++ {
		for r := 0; r < 4; r++ {
			a0 := y[4*c+r]
			a1 := y[4*c+(r+1)%4]
			a2 := y[4*c+(r+2)%4]
			a3 := y[4*c+(r+3)%4]
			out[4*c+r] = xtime(a0) ^ xtime(a1) ^ a1 ^ a2 ^ a3
		}
	}
	return out
}

type state struct {
	s [16][16]byte
}

// Spec 3.2. The returned block is the ciphertext of m.
func (st *state) step(m [16]byte) [16]byte {
	t := xor16(aesRound(xor16(st.s[0], st.s[3])), m)
	c := xor16(t, st.s[8])
	next := xor16(t, aesRound(xor16(st.s[12], st.s[9])))
	st.s[8] = xor16(st.s[8], m)
	var rot [16][16]byte
	copy(rot[:15], st.s[1:])
	rot[15] = next
	st.s = rot
	return c
}

func (st *state) keystream() [16]byte {
	return xor16(aesRound(xor16(st.s[0], st.s[3])), st.s[8])
}

func (st *state) diffuse(x0, x1 [16]byte) {
	for i := 0; i < 16; i++ {
		st.step(x0)
		st.step(x1)
	}
}

func block(src []byte) [16]byte {
	var b [16]byte
	copy(b[:], src)
	return b
}

func newState(key, nonce []byte) state {
	k0, k1 := block(key[:16]), block(key[16:])
	n := block(nonce)
	var st state
	st.s[0] = c0
	st.s[1] = k0
	st.s[2] = c0
	st.s[3] = n
	st.s[5] = k0
	st.s[7] = c1
	st.s[8] = k1
	st.s[10] = xor16(n, k1)
	st.s[11] = c0
	st.s[12] = c1
	st.s[13] = k1
	st.s[15] = xor16(c0, c1)
	st.diffuse(k0, k1)
	// Key feed-forward after the 32 initialization steps, before associated data.
	for i := range st.s {
		if i%2 == 0 {
			st.s[i] = xor16(st.s[i], k0)
		} else {
			st.s[i] = xor16(st.s[i], k1)
		}
	}
	return st
}

func (st *state) absorb(ad []byte) {
	for off := 0; off < len(ad); off += 16 {
		st.step(block(ad[off:]))
	}
}

func (st *state) finalize(adLen, msgLen int) [16]byte {
	var lens [16]byte
	a := uint64(adLen) * 8
	m := uint64(msgLen) * 8
	for i := 0; i < 8; i++ {
		lens[i] = byte(a >> (8 * i))
		lens[8+i] = byte(m >> (8 * i))
	}
	st.diffuse(lens, lens)
	var tag [16]byte
	for i := range st.s {
		tag = xor16(tag, st.s[i])
	}
	return tag
}

// Encrypt returns a new ciphertext and tag. ad and msg may be empty or nil.
// A nonce must never repeat under one key.
func Encrypt(key, nonce, ad, msg []byte) (ct, tag []byte, err error) {
	if len(key) != KeyBytes {
		return nil, nil, ErrKeySize
	}
	if len(nonce) != NonceBytes {
		return nil, nil, ErrNonceSize
	}
	st := newState(key, nonce)
	st.absorb(ad)
	ct = make([]byte, len(msg))
	for off := 0; off < len(msg); off += 16 {
		n := len(msg) - off
		if n > 16 {
			n = 16
		}
		c := st.step(block(msg[off:]))
		copy(ct[off:], c[:n])
	}
	t := st.finalize(len(ad), len(msg))
	return ct, t[:], nil
}

// Decrypt returns the plaintext, or a nil slice and ErrTag if the tag does
// not match. A failing tag does not return plaintext.
func Decrypt(key, nonce, ad, ct, tag []byte) ([]byte, error) {
	if len(key) != KeyBytes {
		return nil, ErrKeySize
	}
	if len(nonce) != NonceBytes {
		return nil, ErrNonceSize
	}
	if len(tag) != TagBytes {
		return nil, ErrTagSize
	}
	st := newState(key, nonce)
	st.absorb(ad)
	msg := make([]byte, len(ct))
	for off := 0; off < len(ct); off += 16 {
		n := len(ct) - off
		if n > 16 {
			n = 16
		}
		ks := st.keystream()
		var m [16]byte
		for j := 0; j < n; j++ {
			m[j] = ct[off+j] ^ ks[j]
		}
		st.step(m)
		copy(msg[off:], m[:n])
	}
	want := st.finalize(len(ad), len(ct))
	if !bytes.Equal(want[:], tag) {
		return nil, ErrTag
	}
	return msg, nil
}
