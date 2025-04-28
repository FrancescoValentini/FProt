package common

import (
	"crypto/ecdsa"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/FrancescoValentini/FProt/digitalsignature"
)

// Encodes ECDSA private and public keys into base64url strings with appropriate headers.
func EncodeECDSAKeys(privateKey *ecdsa.PrivateKey) (string, string, error) {
	privateKeyBytes, err := digitalsignature.PrivateKeyToBytes(privateKey)
	if err != nil {
		return "", "", err
	}

	publicKeyBytes, err := digitalsignature.PublicKeyToBytes(&privateKey.PublicKey)
	if err != nil {
		return "", "", err
	}

	encodedPublic := ECDSA_PUBLIC_KEY_HEADER + base64.RawURLEncoding.EncodeToString(publicKeyBytes)
	encodedPrivate := ECDSA_PRIVATE_KEY_HEADER + base64.RawURLEncoding.EncodeToString(privateKeyBytes)

	return encodedPrivate, encodedPublic, nil
}

// Decodes a base64url-encoded public key string with header.
func DecodeECDSAPublicKey(encodedPublic string) ([]byte, error) {
	if !strings.HasPrefix(encodedPublic, ECDSA_PUBLIC_KEY_HEADER) {
		return nil, fmt.Errorf("%w", ErrInvalidPublicKeyFormat)
	}

	base64Key := strings.TrimPrefix(encodedPublic, ECDSA_PUBLIC_KEY_HEADER)
	decodedKey, err := base64.RawURLEncoding.DecodeString(base64Key)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidBase64, err)
	}

	return decodedKey, nil
}

// Decodes a base64url-encoded private key string with header.
func DecodeECDSAPrivateKey(encodedPrivate string) ([]byte, error) {
	if !strings.HasPrefix(encodedPrivate, ECDSA_PRIVATE_KEY_HEADER) {
		return nil, fmt.Errorf("%w", ErrInvalidPrivateKeyFormat)
	}

	base64Key := strings.TrimPrefix(encodedPrivate, ECDSA_PRIVATE_KEY_HEADER)
	decodedKey, err := base64.RawURLEncoding.DecodeString(base64Key)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidBase64, err)
	}

	return decodedKey, nil
}
