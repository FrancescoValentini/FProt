package digitalsignature

import (
	"crypto/sha512"
	"fmt"
	"io"
	"time"

	"github.com/FrancescoValentini/FProt/ecies"
)

// Generates the structure containing the signature information
func buildSignatureInfo(publicKey []byte, publicKeyID []byte, hash []byte) Signature {
	var pubKeyArray [PublicKeySize]byte
	copy(pubKeyArray[:], publicKey)

	var pubKeyIDArray [PublicKeyIDSize]byte
	copy(pubKeyIDArray[:], ecies.RawPublicKeyID(publicKeyID))

	var contentHashArray [ContentHashSize]byte
	copy(contentHashArray[:], hash)

	sig := Signature{
		Info: SignedInfo{
			Timestamp:   time.Now(),
			PublicKey:   pubKeyArray,
			PublicKeyID: pubKeyIDArray,
			ContentHash: contentHashArray,
		},
	}
	return sig
}

// Calculates the hash of data
func hashData(bufferSize int, input io.Reader) ([]byte, error) {
	hasher := sha512.New384()
	buf := make([]byte, bufferSize)
	for {
		n, err := input.Read(buf)
		if n > 0 {
			hasher.Write(buf[:n])
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrHashing, err)
		}
	}
	computedHash := hasher.Sum(nil)
	return computedHash, nil
}
