package digitalsignature

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"fmt"
	"io"
)

// Generates a new ECDSA private key using the P-384 curve.
func GeneratePrivateKey(rand io.Reader) (*ecdsa.PrivateKey, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrECDSAKeyGeneration, err)
	}
	return priv, nil
}

// Encodes an ECDSA private key to DER (ASN.1, SEC 1 format).
func PrivateKeyToBytes(priv *ecdsa.PrivateKey) ([]byte, error) {
	return x509.MarshalECPrivateKey(priv)
}

// Decodes an ECDSA private key from DER.
func PrivateKeyFromBytes(der []byte) (*ecdsa.PrivateKey, error) {
	priv, err := x509.ParseECPrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrECDSAPrivateKeyLoad, err)
	}
	return priv, nil
}

// Encodes an ECDSA public key to DER (ASN.1, X.509 PKIX format).
func PublicKeyToBytes(pub *ecdsa.PublicKey) ([]byte, error) {
	return x509.MarshalPKIXPublicKey(pub)
}

// Decodes an ECDSA public key from DER.
func PublicKeyFromBytes(der []byte) (*ecdsa.PublicKey, error) {
	pubIface, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrECDSAPublicKeyDecode, err)
	}
	pubKey, ok := pubIface.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("%w: type assertion failed", ErrECDSAPublicKeyLoad)
	}
	return pubKey, nil
}
