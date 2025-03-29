package cryptography

import (
	"encoding/hex"
)

// This method processes either a raw hex-encoded key or a password
// to produce a 256-bit encryption key.
//
// If a hex key is provided, it must be 64 characters long (32 bytes after decoding).
// If a password is provided, it will be derived into a 256-bit key
func ParseKey(keyFlag, passwordFlag string, iv []byte) ([]byte, error) {
	var key []byte
	var err error

	switch {
	case keyFlag != "":
		key, err = hex.DecodeString(keyFlag)
		if err != nil {
			return nil, ErrInvalidHexKey
		}
	case passwordFlag != "":
		key = Derive256BitKey(passwordFlag, iv)
	default:
		return nil, ErrNoKeyOrPassword
	}

	if len(key) != AES_KEY_LENGTH {
		return nil, ErrInvalidKeyLength
	}

	return key, nil
}
