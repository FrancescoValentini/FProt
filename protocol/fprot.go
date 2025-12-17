package protocol

import (
	"bufio"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"os"

	"github.com/FrancescoValentini/FProt/cryptography"
	"github.com/FrancescoValentini/FProt/ecies"
)

// PasswordRecipient creates a password-based recipient for encryption.
//
// Parameters:
//   - password: The password used for key derivation
//   - verboseFlag: If true, prints the Argon2 nonce to stderr
//
// Returns:
//   - Recipient: The constructed recipient with type "ARGON2" and the nonce as body
//   - []byte: The derived 256-bit entropy key
func PasswordRecipient(password string, verboseFlag bool) (Recipient, []byte) {
	nonce, _ := cryptography.GenerateRandomBytes(16)
	rec := Recipient{
		Type: "ARGON2",
		Body: nonce,
	}
	entropy := cryptography.Derive256BitKey(password, nonce)
	if verboseFlag {
		fmt.Fprintln(os.Stderr, "Argon2 Nonce: "+hex.EncodeToString(nonce))
	}
	return rec, entropy
}

// PublicKeyRecipient creates a public-key-based recipient for encryption.
//
// Parameters:
//   - publicKey: The recipient's P-384 public key
//   - entropy: The 256-bit entropy key to be wrapped
//
// Returns:
//   - Recipient: The constructed recipient with type "P384", ephemeral public key as args,
//     and wrapped entropy as body
func PublicKeyRecipient(publicKey []byte, entropy []byte) Recipient {

	wrapped, ephPublic, _ := ecies.ECCWrapKey(publicKey, entropy)
	rec := Recipient{
		Type: "P384",
		Args: []string{base64.StdEncoding.EncodeToString(ephPublic)},
		Body: wrapped,
	}
	return rec
}

// RecoverPasswordEntropy recovers the entropy from password encrypted data.
//
// Parameters:
//   - password: The password used for key derivation
//   - verboseFlag: If true, prints the Argon2 nonce to stderr
//   - r: The input reader containing the encrypted data
//
// Returns:
//   - []byte: The recovered entropy key
//   - io.Reader: A buffered reader positioned at the start of the ciphertext
func RecoverPasswordEntropy(password string, verboseFlag bool, r io.Reader) ([]byte, io.Reader) {
	br := bufio.NewReader(r)

	var header FprotHeader
	if err := header.Unmarshal(br); err != nil {
		panic(err)
	}

	nonce := header.Recipients[0].Body
	entropy := cryptography.Derive256BitKey(password, nonce)

	hmacKey, _ := DeriveKeys(entropy)
	status, _ := header.VerifyHeaderHMAC(hmacKey)
	if !status {
		fmt.Fprintln(os.Stderr, "Error:", ErrHmacVerify)
		os.Exit(1)
	}
	if verboseFlag {
		fmt.Fprintln(os.Stderr, "Argon2 Nonce: "+hex.EncodeToString(nonce))
	}
	return entropy, br
}

// RecoverPublicKeyEntropy recovers the entropy from public-key encrypted data.
// It reads the header and attempts to unwrap the entropy using the provided private key.
// Iterates through all recipients until a successful HMAC verification is found.
//
// Parameters:
//   - privateKeyRaw: The recipient's raw private key
//   - r: The input reader containing the encrypted data
//
// Returns:
//   - []byte: The recovered entropy key
//   - io.Reader: A buffered reader positioned at the start of the ciphertext
func RecoverPublicKeyEntropy(privateKeyRaw []byte, r io.Reader) ([]byte, io.Reader) {
	br := bufio.NewReader(r)

	var header FprotHeader
	if err := header.Unmarshal(br); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
	var status bool
	recipients := header.Recipients
	for _, recipient := range recipients { // for each recipient try to verify the hmac
		wrapped := recipient.Body
		ephPublic, _ := base64.StdEncoding.DecodeString(recipient.Args[0])
		privateKey, err := ecies.LoadPrivateKey(privateKeyRaw)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Error:", err)
			os.Exit(1)
		}
		entropy, _ := ecies.ECCUnwrapKey(privateKey, ephPublic, wrapped)

		hmacKey, _ := DeriveKeys(entropy)
		status, _ = header.VerifyHeaderHMAC(hmacKey)

		if status { // first match
			return entropy, br // br is positioned at the ciphertext
		}
	}

	if !status { // If the hmac verification fails
		fmt.Fprintln(os.Stderr, "Error:", ErrHmacOrNoMatchingPrivate)
		os.Exit(1)
	}

	return nil, nil
}

// Encrypt encrypts data using the provided recipients and entropy.
//
// Parameters:
//   - recipients: List of recipients who can decrypt the data
//   - entropy
//   - input: Reader providing the plaintext data
//   - output: Writer where encrypted data will be written
//
// Returns:
//   - uint64: Number of encrypted chunks processed
func Encrypt(recipients []Recipient, entropy []byte, input io.Reader, output io.Writer) uint64 {
	// 1) Derive keys
	macKey, fileKey := DeriveKeys(entropy)

	// 2) write header
	writeHeader(recipients, macKey, output)

	// 3) Encryption
	aesGCM, err := cryptography.GetAESGCM(fileKey)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error creating GCM:", err)
		os.Exit(1)
	}
	chunks, err := cryptography.Encrypt(aesGCM, cryptography.BUFFER_SIZE, input, output)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Encryption failed: %v\n", err)
		os.Exit(1)
	}
	return chunks
}

// Decrypt decrypts data using the provided entropy key.
//
// Parameters:
//   - entropy
//   - input: Reader providing the ciphertext data (positioned after the header)
//   - output: Writer where decrypted data will be written
//
// Returns:
//   - uint64: Number of decrypted chunks processed
func Decrypt(entropy []byte, input io.Reader, output io.Writer) uint64 {
	// 1) Derive keys
	_, fileKey := DeriveKeys(entropy)

	// 2) Decrypt
	aesGCM, err := cryptography.GetAESGCM(fileKey)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error creating GCM:", err)
		os.Exit(1)
	}
	chunks, err := cryptography.Decrypt(aesGCM, cryptography.BUFFER_SIZE, input, output)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Decryption failed: %v\n", err)
		os.Exit(1)
	}
	return chunks
}

// writeHeader creates and writes the file header.
//
// Parameters:
//   - recipients: List of recipients
//   - macKey: The HMAC key
//   - output: Writer where the header will be written
func writeHeader(recipients []Recipient, macKey []byte, output io.Writer) {
	header := FprotHeader{
		Version:    "fprot/v1",
		Recipients: recipients,
	}
	header.Marshal(output, macKey)
}

// DeriveKeys derives the HMAC key and file encryption key from the master entropy.
//
// Parameters:
//   - entropy
//
// Returns:
//   - []byte: HMAC key for header integrity (32 bytes)
//   - []byte: File encryption key for AES-GCM (32 bytes)
func DeriveKeys(entropy []byte) ([]byte, []byte) {
	hmacKey := deriveKey(entropy, []byte("HMAC_SALT"), []byte(HMAC_KEY_KDFINFO), 32)
	fileKey := deriveKey(entropy, []byte("FILE_SALT"), []byte(FILE_KEY_KDFINFO), 32)
	return hmacKey, fileKey
}
