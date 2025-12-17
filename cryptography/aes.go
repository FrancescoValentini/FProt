/*
MIT License

# Copyright (c) 2025 Francesco Valentini

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

package cryptography

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"os"
)

// This method returns the 128-bit block cipher initialized with the given key
// it wraps the NewGCMWithNonceSize setting the nonce size to 128-bit as recommended
// by NIST Special Publication 800-38D, Section. 8.2.2
func GetAESGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesGCM, err := cipher.NewGCMWithNonceSize(block, GCM_NONCE_LENGTH)
	return aesGCM, err
}

// buildNonce constructs a 96-bit GCM nonce:
// 32-bit random prefix + 64-bit counter.
func buildNonce(random []byte, counter uint64) []byte {
	nonce := make([]byte, GCM_NONCE_LENGTH)
	copy(nonce[:RANDOM_SIZE], random)
	binary.BigEndian.PutUint64(nonce[RANDOM_SIZE:], counter)

	fmt.Fprintf(os.Stderr, "RANDOM  : %s\n", hex.EncodeToString(random))
	counterBuf := make([]byte, COUNTER_SIZE)
	binary.BigEndian.PutUint64(counterBuf, counter)
	fmt.Fprintf(os.Stderr, "COUNTER : %s\n", hex.EncodeToString(counterBuf))
	fmt.Fprintf(os.Stderr, "NONCE   : %s\n", hex.EncodeToString(nonce))
	return nonce
}

// buildAAD constructs authenticated associated data.
// We authenticate the counter and ciphertext length.
func buildAAD(counter uint64, clen uint32) []byte {
	aad := make([]byte, COUNTER_SIZE+LEN_FIELD_SIZE)
	binary.BigEndian.PutUint64(aad[:COUNTER_SIZE], counter)
	binary.BigEndian.PutUint32(aad[COUNTER_SIZE:], clen)
	return aad
}

// Encrypt reads, encrypts, and writes data in chunks.
// Each chunk uses a unique nonce composed of:
//   - 32-bit random value (per chunk)
//   - 64-bit monotonically increasing counter
//
// Output format per chunk:
//
//	[random:4][counter:8][ciphertext length:4][ciphertext||tag]
//
// NOTE: bufferSize is multiplied by 1024.
func Encrypt(
	aesGCM cipher.AEAD,
	bufferSize int,
	input io.Reader,
	output io.Writer,
) (uint64, error) {

	buffer := make([]byte, bufferSize*1024)
	counter := uint64(0)
	tagLen := aesGCM.Overhead()

	for {
		n, err := input.Read(buffer)
		if err != nil && err != io.EOF {
			return 0, fmt.Errorf("%w: %v", ErrReadFailed, err)
		}

		if n > 0 {
			// Generate random part per chunk
			randomPart, err := GenerateRandomBytes(RANDOM_SIZE)
			if err != nil {
				return 0, fmt.Errorf("%w: %v", ErrIVGenerationFailed, err)
			}

			nonce := buildNonce(randomPart, counter)

			// Ciphertext length = plaintext + GCM tag
			clen := uint32(n + tagLen)

			// Build AAD: counter + ciphertext length
			aad := buildAAD(counter, clen)

			// Encrypt once
			ciphertext := aesGCM.Seal(nil, nonce, buffer[:n], aad)

			// Write random part
			if _, err := output.Write(randomPart); err != nil {
				return 0, err
			}

			// Write counter
			counterBuf := make([]byte, COUNTER_SIZE)
			binary.BigEndian.PutUint64(counterBuf, counter)
			if _, err := output.Write(counterBuf); err != nil {
				return 0, err
			}

			// Write ciphertext length
			lenBuf := make([]byte, LEN_FIELD_SIZE)
			binary.BigEndian.PutUint32(lenBuf, clen)
			if _, err := output.Write(lenBuf); err != nil {
				return 0, err
			}

			// Write ciphertext + tag
			if _, err := output.Write(ciphertext); err != nil {
				return 0, err
			}

			counter++
		}

		if err == io.EOF {
			break
		}
	}

	return counter, nil
}

// Decrypt reads, decrypts, and writes data in chunks,
// verifying integrity, authenticity, and strict chunk ordering.
//
// Expected input format per chunk:
//
//	[random:4][counter:8][ciphertext length:4][ciphertext||tag]
//
// NOTE: bufferSize is multiplied by 1024.
func Decrypt(
	aesGCM cipher.AEAD,
	bufferSize int,
	input io.Reader,
	output io.Writer,
) (uint64, error) {

	randomPart := make([]byte, RANDOM_SIZE)
	counterBuf := make([]byte, COUNTER_SIZE)
	lenBuf := make([]byte, LEN_FIELD_SIZE)

	expectedCounter := uint64(0)

	for {
		// Read random part
		if _, err := io.ReadFull(input, randomPart); err != nil {
			if err == io.EOF {
				break
			}
			return 0, fmt.Errorf("%w: %v", ErrIVReadFailed, err)
		}

		// Read counter from file
		if _, err := io.ReadFull(input, counterBuf); err != nil {
			return 0, fmt.Errorf("%w: %v", ErrCounterReadFailed, err)
		}

		chunkCounter := binary.BigEndian.Uint64(counterBuf)
		if chunkCounter != expectedCounter {
			return 0, fmt.Errorf(
				"%w: expected %d, got %d",
				ErrChunkMissmatch,
				expectedCounter,
				chunkCounter,
			)
		}

		// Read ciphertext length
		if _, err := io.ReadFull(input, lenBuf); err != nil {
			return 0, err
		}

		clen := binary.BigEndian.Uint32(lenBuf)

		// Read ciphertext + tag
		ciphertext := make([]byte, clen)
		if _, err := io.ReadFull(input, ciphertext); err != nil {
			return 0, err
		}

		nonce := buildNonce(randomPart, chunkCounter)
		aad := buildAAD(chunkCounter, clen)

		// Decrypt and authenticate
		plaintext, err := aesGCM.Open(nil, nonce, ciphertext, aad)
		if err != nil {
			return 0, fmt.Errorf("%w: %v", ErrDecryptionFailed, err)
		}

		if _, err := output.Write(plaintext); err != nil {
			return 0, err
		}

		expectedCounter++
	}

	return expectedCounter, nil
}
