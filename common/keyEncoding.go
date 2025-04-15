package main

import (
	"crypto/ecdh"
	"encoding/base64"
	"fmt"
	"strings"
)

// Encodes ECC private and public keys into base64url strings with appropriate headers.
func EncodeECCKeys(privateKey *ecdh.PrivateKey) (string, string) {
	publicKeyBytes := privateKey.PublicKey().Bytes()
	privateKeyBytes := privateKey.Bytes()

	encodedPublic := PUBLIC_KEY_HEADER + base64.RawURLEncoding.EncodeToString(publicKeyBytes)
	encodedPrivate := PRIVATE_KEY_HEADER + base64.RawURLEncoding.EncodeToString(privateKeyBytes)

	return encodedPrivate, encodedPublic
}

// Decodes a base64url-encoded public key string with header.
func DecodePublicKey(encodedPublic string) ([]byte, error) {
	if !strings.Contains(encodedPublic, PUBLIC_KEY_HEADER) {
		return nil, fmt.Errorf("%w", ErrInvalidPublicKeyFormat)
	}

	base64Key := strings.TrimPrefix(encodedPublic, PUBLIC_KEY_HEADER)
	decodedKey, err := base64.RawURLEncoding.DecodeString(base64Key)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidBase64, err)
	}

	return decodedKey, nil
}

// Decodes a base64url-encoded private key string with header.
func DecodePrivateKey(encodedPrivate string) ([]byte, error) {
	if !strings.Contains(encodedPrivate, PRIVATE_KEY_HEADER) {
		return nil, fmt.Errorf("%w", ErrInvalidPrivateKeyFormat)
	}

	base64Key := strings.TrimPrefix(encodedPrivate, PRIVATE_KEY_HEADER)
	decodedKey, err := base64.RawURLEncoding.DecodeString(base64Key)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidBase64, err)
	}

	return decodedKey, nil
}
