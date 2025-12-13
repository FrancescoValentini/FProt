package common

import (
	"strings"
)

// Loads a public key from either a direct string input or a file.
func LoadPublic(publicKey string) ([]byte, error) {
	if strings.Contains(publicKey, PUBLIC_KEY_HEADER) {
		key, err := DecodePublicKey(publicKey)
		if err != nil {
			return nil, err
		}
		return key, nil
	} else {
		encoded, err := ReadFile(publicKey)
		if err != nil {
			return nil, err
		}
		key, err := DecodePublicKey(encoded)
		if err != nil {
			return nil, err
		}
		return key, nil
	}
}

// Loads a private key from either a direct string input or a file.
func LoadPrivate(privateKey string) ([]byte, error) {
	if strings.Contains(privateKey, PRIVATE_KEY_HEADER) {
		key, err := DecodePrivateKey(privateKey)
		if err != nil {
			return nil, err
		}
		return key, nil
	} else {
		encoded, err := ReadFile(privateKey)
		if err != nil {
			return nil, err
		}
		key, err := DecodePrivateKey(encoded)
		if err != nil {
			return nil, err
		}
		return key, nil
	}
}
