package common

import "strings"

// Loads a public key from either a direct string input or a file.
func LoadECDSAPublic(publicKey string) ([]byte, error) {
	if strings.Contains(publicKey, ECDSA_PUBLIC_KEY_HEADER) {
		key, err := DecodeECDSAPublicKey(publicKey)
		if err != nil {
			return nil, err
		}
		return key, nil
	} else {
		encoded, err := ReadFile(publicKey)
		if err != nil {
			return nil, err
		}
		key, err := DecodeECDSAPublicKey(encoded)
		if err != nil {
			return nil, err
		}
		return key, nil
	}
}

// Loads a private key from either a direct string input or a file.
func LoadECDSAPrivate(privateKey string) ([]byte, error) {
	if strings.Contains(privateKey, ECDSA_PRIVATE_KEY_HEADER) {
		key, err := DecodeECDSAPrivateKey(privateKey)
		if err != nil {
			return nil, err
		}
		return key, nil
	} else {
		encoded, err := ReadFile(privateKey)
		if err != nil {
			return nil, err
		}
		key, err := DecodeECDSAPrivateKey(encoded)
		if err != nil {
			return nil, err
		}
		return key, nil
	}
}
