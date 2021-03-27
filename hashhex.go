package cryptoutils

import (
	"crypto/sha256"
	"encoding/hex"
)

func Hash256Hex(s string) string {
	h := sha256.New()
	h.Write([]byte(s))
	var out []byte
	out = h.Sum(nil)
	return hex.EncodeToString(out)
}

func Hash256(s string) []byte {
	h := sha256.New()
	h.Write([]byte(s))
	var out []byte
	out = h.Sum(nil)
	return out
	// return hex.EncodeToString(out);
}

func HashBytes(s []byte) []byte {
	h := sha256.New()
	h.Write(s)
	var out []byte
	out = h.Sum(nil)
	return out
}

func HashBytes256Hex(s []byte) string {
	h := sha256.New()
	h.Write(s)
	var out []byte
	out = h.Sum(nil)
	return hex.EncodeToString(out)
}
