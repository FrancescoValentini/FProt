package digitalsignature

import "fmt"

// ECDSA key related errors
var (
	ErrECDSAKeyGeneration   = fmt.Errorf("ECDSA key generation failed")
	ErrECDSAPublicKeyLoad   = fmt.Errorf("ECDSA public key loading failed")
	ErrECDSAPrivateKeyLoad  = fmt.Errorf("ECDSA private key loading failed")
	ErrECDSAPublicKeyDecode = fmt.Errorf("ECDSA public key decoding failed")
)

// Signature errors
var (
	ErrInvalidDataSize  = fmt.Errorf("insufficient data length")
	ErrHashing          = fmt.Errorf("error while hashing")
	ErrSign             = fmt.Errorf("error while signing")
	ErrInvalidSignature = fmt.Errorf("invalid digital signature")
)
