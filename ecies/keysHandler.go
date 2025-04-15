package ecies

import (
	"crypto/ecdh"
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
