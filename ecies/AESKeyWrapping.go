package ecies

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
)

// Returns the 128-bit block cipher initialized with the given key
// The IV size is the standard 12 bytes
func getGCMCipher(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCipherCreation, err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrGCMCreation, err)
	}
	return gcm, nil
}

// WrapKey encrypts (wraps) a key using AES-GCM
func aesWrapKey(keyToWrap, wrappingKey []byte) ([]byte, error) {
	gcm, err := getGCMCipher(wrappingKey)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNonceGeneration, err)
	}

	// Encrypt the key
	ciphertext := gcm.Seal(nil, nonce, keyToWrap, nil)

	// Prepend the nonce to the ciphertext
	wrappedKey := safeConcat(nonce, ciphertext)

	return wrappedKey, nil
}

// UnwrapKey decrypts (unwraps) a key using AES-GCM
func aesUnwrapKey(wrappedKey, wrappingKey []byte) ([]byte, error) {
	gcm, err := getGCMCipher(wrappingKey)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(wrappedKey) < nonceSize {
		return nil, fmt.Errorf("%w: %v", ErrInvalidWrappedKeyLength, err)
	}

	nonce, ciphertext := wrappedKey[:nonceSize], wrappedKey[nonceSize:]

	// Decrypt the key
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDecryptionFailed, err)
	}

	return plaintext, nil
}
