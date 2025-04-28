package digitalsignature

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha512"
	"fmt"
	"io"
	"time"

	"github.com/FrancescoValentini/FProt/ecies"
)

// Sign data
func Sign(privateKey *ecdsa.PrivateKey, bufferSize int, input io.Reader) ([]byte, error) {
	bufferSize = bufferSize * 1024
	publicKeyBytes, err := PublicKeyToBytes(&privateKey.PublicKey)
	if err != nil {
		return nil, err
	}

	//1) Hash the data
	contentHash, err := hashData(bufferSize, input)
	if err != nil {
		return nil, err
	}

	//2) Build the data structure
	sig := buildSignatureInfo(publicKeyBytes, contentHash)

	//3) Sign
	bytesToSign := sig.Info.ToBytes()
	sig.SignedData, err = ecdsa.SignASN1(rand.Reader, privateKey, bytesToSign[:])
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSign, err)
	}

	//4) Serialize
	return sig.ToBytes(), nil
}

// Verify a digital signature
func Verify(signature []byte, bufferSize int, input io.Reader) (bool, SignedInfo, error) {
	//1) Hash the data
	contentHash, err := hashData(bufferSize, input)
	if err != nil {
		return false, SignedInfo{}, err
	}
	//2) Deserialize signature
	var decodedSig Signature
	if err := decodedSig.FromBytes(signature); err != nil {
		return false, SignedInfo{}, err
	}
	//3) Check signature
	publicKey, err := PublicKeyFromBytes(decodedSig.Info.PublicKey[:])
	if err != nil {
		return false, SignedInfo{}, err
	}
	infoBytes := decodedSig.Info.ToBytes()
	if !ecdsa.VerifyASN1(publicKey, infoBytes, decodedSig.SignedData[:]) {
		return false, SignedInfo{}, fmt.Errorf("%w", ErrInvalidSignature)
	}

	//4) Check hash
	if !bytes.Equal(decodedSig.Info.ContentHash[:], contentHash) {
		return false, SignedInfo{}, nil
	}

	return true, decodedSig.Info, nil
}

// Generates the structure containing the signature information
func buildSignatureInfo(publicKey []byte, hash []byte) Signature {
	var pubKeyArray [PublicKeySize]byte
	copy(pubKeyArray[:], publicKey)

	var pubKeyIDArray [PublicKeyIDSize]byte
	copy(pubKeyIDArray[:], ecies.RawPublicKeyID(publicKey))

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
