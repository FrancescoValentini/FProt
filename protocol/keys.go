package protocol

import (
	"crypto/sha512"
	"io"

	"golang.org/x/crypto/hkdf"
)

// Derive a key using HKDF with sha384
func deriveKey(seed []byte, salt []byte, info []byte, size int) []byte {
	hkdfReader := hkdf.New(sha512.New384, seed, salt, info)
	secretKey := make([]byte, size)
	io.ReadFull(hkdfReader, secretKey)
	return secretKey
}
