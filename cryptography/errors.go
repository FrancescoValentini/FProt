package cryptography

import "errors"

// Key errors
var (
	ErrNoKeyOrPassword  = errors.New("no key or password provided")
	ErrInvalidKeyLength = errors.New("invalid key length (must be 32 bytes)")
	ErrInvalidHexKey    = errors.New("key is not a valid hex string")
)

// I/O Errors
var (
	ErrReadFailed         = errors.New("read operation failed")
	ErrWriteFailed        = errors.New("write operation failed")
	ErrIVReadFailed       = errors.New("failed to read initialization vector")
	ErrIVWriteFailed      = errors.New("failed to write initialization vector")
	ErrCounterReadFailed  = errors.New("failed to read counter")
	ErrCounterWriteFailed = errors.New("failed to write counter")
	ErrIVGenerationFailed = errors.New("failed to generate initialization vector")
)

// Cipher errors
var (
	ErrDecryptionFailed = errors.New("failed to decrypt")
	ErrChunkMissmatch   = errors.New("chunk counter mismatch")
)
