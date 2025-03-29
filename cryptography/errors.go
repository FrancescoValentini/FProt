package cryptography

import "errors"

// Key errors
var (
	ErrNoKeyOrPassword  = errors.New("no key or password provided")
	ErrInvalidKeyLength = errors.New("invalid key length (must be 32 bytes)")
	ErrInvalidHexKey    = errors.New("key is not a valid hex string")
)
