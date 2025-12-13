package ecies

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha512"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

// Encrypts a symmetric key for a recipient using their public key.
func ECCWrapKey(recipient []byte, key []byte) ([]byte, []byte, error) {
	// 1) Loads the recipient public key
	recipientPublicKey, err := LoadPublicKey(recipient)
	if err != nil {
		return nil, nil, err
	}

	// 2) Generates the ephemeral EC key
	ephemeralPrivateKey, err := GeneratePrivateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	ephemeralPub := ephemeralPrivateKey.PublicKey().Bytes()

	// 3) Generates the shared secret
	sharedSecret, err := ephemeralPrivateKey.ECDH(recipientPublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrSharedSecret, err)
	}

	// 4) Derives the AES Wrap key
	salt := safeConcat(ephemeralPub, recipient)
	wrappingKey := deriveSecretKey(sharedSecret, salt, []byte(HKDF_INFO_SHARED_SECRET), 32)

	// 5) Wraps the key
	encryptedKey, err := aesWrapKey(key, wrappingKey)
	if err != nil {
		return nil, nil, err
	}

	// encryptedKey = iv + ciphertext + authTag

	return encryptedKey, ephemeralPub, nil
}

// Decrypts a symmetric key that was wrapped using ECIES
func ECCUnwrapKey(privateKey *ecdh.PrivateKey, ephemeralPubBytes []byte, encryptedKey []byte) ([]byte, error) {
	ephemeralPubKey, err := LoadPublicKey(ephemeralPubBytes)
	if err != nil {
		return nil, err
	}

	//2) Calculates the shared secret
	sharedSecret, err := privateKey.ECDH(ephemeralPubKey)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSharedSecret, err)
	}

	//3) Derives the AES Wrap key
	recipient := privateKey.PublicKey().Bytes()
	salt := safeConcat(ephemeralPubBytes, recipient)

	wrappingKey := deriveSecretKey(sharedSecret, salt, []byte(HKDF_INFO_SHARED_SECRET), 32)

	//4) Unwraps the key
	return aesUnwrapKey(encryptedKey, wrappingKey)
}

// Derives a secret key of the specified size using HKDF
func deriveSecretKey(seed []byte, salt []byte, info []byte, size int) []byte {
	hkdfReader := hkdf.New(sha512.New384, seed, salt, info)
	secretKey := make([]byte, size)
	io.ReadFull(hkdfReader, secretKey)
	return secretKey
}
