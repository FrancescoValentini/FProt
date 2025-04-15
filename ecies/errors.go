package ecies

import "errors"

// ECC Errors
var (
	ErrECCKeyGeneration  = errors.New("failed to generate private key")
	ErrECCPublicKeyLoad  = errors.New("failed to load public key")
	ErrECCPrivateKeyLoad = errors.New("failed to load private key")
)
