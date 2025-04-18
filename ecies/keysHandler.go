package ecies

import (
	"crypto/ecdh"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"io"
)

// Generates a new ECDH private key using the P-384 curve.
func GeneratePrivateKey(rand io.Reader) (*ecdh.PrivateKey, error) {
	ephemeralPriv, err := ecdh.P384().GenerateKey(rand)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrECCKeyGeneration, err)
	}
	return ephemeralPriv, err
}

// Loads a public key from its byte representation using the P-384 curve.
func LoadPublicKey(publicKeyBytes []byte) (*ecdh.PublicKey, error) {
	pubKey, err := ecdh.P384().NewPublicKey(publicKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrECCPublicKeyLoad, err)
	}
	return pubKey, err
}

// Loads a private key from its byte representation using the P-384 curve.
func LoadPrivateKey(privateKeyBytes []byte) (*ecdh.PrivateKey, error) {
	privKey, err := ecdh.P384().NewPrivateKey(privateKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrECCPrivateKeyLoad, err)
	}
	return privKey, err
}

// Generates a truncated SHA-384 hash of the input data
// to use as a raw public key ID.
func rawPublicKeyID(data []byte) []byte {
	hash := sha512.Sum384(data) // 48 bytes
	truncated := hash[:20]      // 20 bytes
	return truncated
}

// Generates a base64 URL-encoded string representation of a public key ID.
func GetPublicKeyID(rawPublicKey []byte) string {
	rawId := rawPublicKeyID(rawPublicKey)
	encoded := base64.RawURLEncoding.EncodeToString(rawId)
	return encoded
}

// Verifies whether the given ID string matches the public key ID
func VerifyPublicKeyID(id string, rawPublicKey []byte) bool {
	rawId := rawPublicKeyID(rawPublicKey)
	encoded := base64.RawURLEncoding.EncodeToString(rawId)
	return encoded == id
}
