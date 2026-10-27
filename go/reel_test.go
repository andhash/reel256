package reel

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"testing"
)

func TestSBox(t *testing.T) {
	if sbox[0] != 0x63 || sbox[1] != 0x7c || sbox[255] != 0x16 {
		t.Fatalf("S-box %02x %02x %02x", sbox[0], sbox[1], sbox[255])
	}
}

func TestVectors(t *testing.T) {
	raw, err := os.ReadFile("../test-vectors/reel256.json")
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Algorithm string `json:"algorithm"`
		Vectors   []struct {
			Name  string `json:"name"`
			Key   string `json:"key"`
			Nonce string `json:"nonce"`
			AD    string `json:"ad"`
			Msg   string `json:"msg"`
			CT    string `json:"ct"`
			Tag   string `json:"tag"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatal(err)
	}
	if file.Algorithm != "Reel-256" || len(file.Vectors) != 12 {
		t.Fatalf("file %q vectors %d", file.Algorithm, len(file.Vectors))
	}
	for _, v := range file.Vectors {
		key := mustHex(t, v.Key)
		nonce := mustHex(t, v.Nonce)
		ad := mustHex(t, v.AD)
		msg := mustHex(t, v.Msg)
		ct := mustHex(t, v.CT)
		tag := mustHex(t, v.Tag)
		gotCT, gotTag, err := Encrypt(key, nonce, ad, msg)
		if err != nil {
			t.Fatalf("%s: encrypt: %v", v.Name, err)
		}
		if !bytes.Equal(gotCT, ct) || !bytes.Equal(gotTag, tag) {
			t.Fatalf("%s: encrypt mismatch", v.Name)
		}
		got, err := Decrypt(key, nonce, ad, ct, tag)
		if err != nil || !bytes.Equal(got, msg) {
			t.Fatalf("%s: decrypt %v", v.Name, err)
		}
		bad := bytes.Clone(tag)
		bad[0] ^= 1
		got, err = Decrypt(key, nonce, ad, ct, bad)
		if !errors.Is(err, ErrTag) || got != nil {
			t.Fatalf("%s: bad tag returned %v, %d bytes", v.Name, err, len(got))
		}
	}
}

func TestLengths(t *testing.T) {
	key := bytes.Repeat([]byte{1}, KeyBytes)
	nonce := bytes.Repeat([]byte{2}, NonceBytes)
	if _, _, err := Encrypt(key[:31], nonce, nil, nil); !errors.Is(err, ErrKeySize) {
		t.Fatal(err)
	}
	if _, _, err := Encrypt(key, nonce[:15], nil, nil); !errors.Is(err, ErrNonceSize) {
		t.Fatal(err)
	}
	if _, err := Decrypt(key, nonce, nil, nil, []byte{0}); !errors.Is(err, ErrTagSize) {
		t.Fatal(err)
	}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
