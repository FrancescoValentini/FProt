package common

import (
	"encoding/base64"
	"fmt"
	"strings"
)

// Encodes a digital signature in base64url
func EncodeArmor(signature []byte) string {
	encode := base64.RawURLEncoding.EncodeToString(signature)
	return SIGNATURE_HEADER + encode
}

// Decodes a digital signature in base64url
func DecodeArmor(signature string) ([]byte, error) {
	if strings.Contains(signature, SIGNATURE_HEADER) {
		base64sig := strings.TrimPrefix(signature, SIGNATURE_HEADER)

		decoded, err := base64.RawURLEncoding.DecodeString(base64sig)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalidBase64, err)
		}
		return decoded, nil
	}
	return nil, fmt.Errorf("%w", ErrInvalidDigitalSignatureFormat)
}
