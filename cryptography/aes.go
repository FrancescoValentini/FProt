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
	"fmt"
	"io"
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

// Encrypt reads, encrypts, and writes data in chunks, each with its own IV and authentication tag.
// The IV is prepended to each encrypted chunk, and the tag is appended.
//
// Note: The buffer size is multiplied by 1024.
func Encrypt(aesGCM cipher.AEAD, bufferSize int, input io.Reader, output io.Writer) (uint32, error) {
	buffer := make([]byte, bufferSize*1024)
	counter := uint32(0)

	for {
		n, err := input.Read(buffer)
		if err != nil && err != io.EOF {
			return 0, fmt.Errorf("%w: %v", ErrReadFailed, err)
		}

		if n > 0 {
			iv, err := GenerateRandomBytes(GCM_NONCE_LENGTH)
			if err != nil {
				return 0, fmt.Errorf("%w: %v", ErrIVGenerationFailed, err)
			}

			counterBytes := make([]byte, COUNTER_SIZE)
			binary.BigEndian.PutUint32(counterBytes, counter)

			// Encrypt
			ciphertext := aesGCM.Seal(nil, iv, buffer[:n], counterBytes)

			// Write IV
			if _, err := output.Write(iv); err != nil {
				return 0, err
			}

			// Write counter
			if _, err := output.Write(counterBytes); err != nil {
				return 0, err
			}

			// Write ciphertext length
			lenBuf := make([]byte, 4)
			binary.BigEndian.PutUint32(lenBuf, uint32(len(ciphertext)))
			if _, err := output.Write(lenBuf); err != nil {
				return 0, err
			}

			// Write ciphertext+tag
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

// Decrypt reads, decrypts, and writes data in chunks, verifying each chunk's authentication tag.
//
// Note: The buffer size is multiplied by 1024.
func Decrypt(aesGCM cipher.AEAD, bufferSize int, input io.Reader, output io.Writer) (uint32, error) {
	iv := make([]byte, GCM_NONCE_LENGTH)
	counterBytes := make([]byte, COUNTER_SIZE)
	lenBuf := make([]byte, 4)

	expectedCounter := uint32(0)

	for {
		// Read IV
		if _, err := io.ReadFull(input, iv); err != nil {
			if err == io.EOF {
				break
			}
			return 0, fmt.Errorf("%w: %v", ErrIVReadFailed, err)
		}

		// Read counter
		if _, err := io.ReadFull(input, counterBytes); err != nil {
			return 0, fmt.Errorf("%w: %v", ErrCounterReadFailed, err)
		}

		chunkCounter := binary.BigEndian.Uint32(counterBytes)
		if chunkCounter != expectedCounter {
			return 0, fmt.Errorf(
				"%w: Expected %d, got %d",
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

		// Read ciphertext+tag
		ciphertext := make([]byte, clen)
		if _, err := io.ReadFull(input, ciphertext); err != nil {
			return 0, err
		}

		// Decrypt
		plaintext, err := aesGCM.Open(nil, iv, ciphertext, counterBytes)
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
