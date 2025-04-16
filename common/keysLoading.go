package common

import (
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/FrancescoValentini/FProt/cryptography"
	"github.com/FrancescoValentini/FProt/ecies"
)

// Generates or parses a symmetric encryption key.
// It takes a keyFlag (either raw key material or a path to a key file),
// passwordFlag (optional password for key derivation), and verboseFlag
// (to enable debug output). Returns the derived key as a byte slice.
// If passwordFlag is provided, it writes the initialization vector to stdout.
func SymmetricKey(keyFlag string, passwordFlag string, verboseFlag bool) []byte {
	nonce, _ := cryptography.GenerateRandomBytes(16)                // Generates a random nonce
	key, err := cryptography.ParseKey(keyFlag, passwordFlag, nonce) // parses the key
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}

	if passwordFlag != "" {
		cryptography.WriteIV(nonce, os.Stdout)
	}

	if verboseFlag {
		fmt.Fprintln(os.Stderr, "Argon2 Nonce: "+hex.EncodeToString(nonce))
	}
	return key
}

// Generates a random symmetric key and encrypts it
// for the specified recipient using ECC (Elliptic Curve Cryptography).
// The encrypted key is written to the provided writer 'w'.
// Returns the generated symmetric key as a byte slice.
func EncryptAsymmetricKey(recipient string, w io.Writer) []byte {
	key, err := cryptography.GenerateRandomBytes(32) // generates a random 256 bit key
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}

	rawPublic, err := LoadPublic(recipient)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}

	wrappedKey, err := ecies.ECCWrapKey(rawPublic, key)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}

	if _, err := w.Write(wrappedKey); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}

	return key
}

// Reads an encrypted symmetric key from the reader 'r'
// and decrypts it using the specified private key.
// Returns the decrypted symmetric key as a byte slice.
func DecryptAsymmetricKey(privateKey string, r io.Reader) []byte {
	rawPrivate, err := LoadPrivate(privateKey)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}

	wrappedKey, err := readWrappedKey(r)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}

	eccPrivateKey, err := ecies.LoadPrivateKey(rawPrivate)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
	key, err := ecies.ECCUnwrapKey(eccPrivateKey, wrappedKey)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}

	return key
}

// Reads the wrapped key from the reader 'r'.
// The wrapped key format consists of:
// ECDH public key + WRAPPED_256_BIT_KEY
// where WRAPPED_256_BIT_KEY = AES_GCM_IV + ENCRYPTED_256_BIT_KEY + AES_GCM_128_BIT_AUTH
// Returns the wrapped key as a byte slice or an error if reading fails.
func readWrappedKey(r io.Reader) ([]byte, error) {
	headerSize := ecies.CURVE_PUBLIC_KEY_LENGTH + 60
	header := make([]byte, headerSize)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, err
	}
	return header, nil
}

// Loads a public key from either a direct string input or a file.
func LoadPublic(publicKey string) ([]byte, error) {
	if strings.Contains(publicKey, PUBLIC_KEY_HEADER) {
		key, err := DecodePublicKey(publicKey)
		if err != nil {
			return nil, err
		}
		return key, nil
	} else {
		encoded, err := ReadFile(publicKey)
		if err != nil {
			return nil, err
		}
		key, err := DecodePublicKey(encoded)
		if err != nil {
			return nil, err
		}
		return key, nil
	}
}

// Loads a private key from either a direct string input or a file.
func LoadPrivate(privateKey string) ([]byte, error) {
	if strings.Contains(privateKey, PRIVATE_KEY_HEADER) {
		key, err := DecodePrivateKey(privateKey)
		if err != nil {
			return nil, err
		}
		return key, nil
	} else {
		encoded, err := ReadFile(privateKey)
		if err != nil {
			return nil, err
		}
		key, err := DecodePrivateKey(encoded)
		if err != nil {
			return nil, err
		}
		return key, nil
	}
}
