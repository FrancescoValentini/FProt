package ecies

import "errors"

// ECC Errors
var (
	ErrECCKeyGeneration  = errors.New("failed to generate private key")
	ErrECCPublicKeyLoad  = errors.New("failed to load public key")
	ErrECCPrivateKeyLoad = errors.New("failed to load private key")
)

// AES KeyWrap errors
var (
	ErrCipherCreation          = errors.New("failed to create cipher")
	ErrGCMCreation             = errors.New("failed to create GCM mode")
	ErrNonceGeneration         = errors.New("failed to generate nonce")
	ErrInvalidWrappedKeyLength = errors.New("wrapped key is too short")
	ErrDecryptionFailed        = errors.New("decryption failed")
)
