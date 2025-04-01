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
func Encrypt(aesGCM cipher.AEAD, bufferSize int, input io.Reader, output io.Writer) error {
	buffer := make([]byte, bufferSize*1024)

	for {
		n, err := input.Read(buffer)
		if err != nil && err != io.EOF {
			return fmt.Errorf("%w: %v", ErrReadFailed, err)
		}

		if n > 0 {
			// Generate unique IV for each chunk
			iv, err := GenerateRandomBytes(GCM_NONCE_LENGTH)
			if err != nil {
				return fmt.Errorf("%w: %v", ErrIVGenerationFailed, err)
			}

			// Write IV to output
			if err := WriteIV(iv, output); err != nil {
				return fmt.Errorf("%w: %v", ErrIVWriteFailed, err)
			}

			if err := encryptChunk(aesGCM, iv, buffer[:n], output); err != nil {
				return fmt.Errorf("%w: %v", ErrWriteFailed, err)
			}

		}

		if err == io.EOF {
			break
		}
	}
	return nil
}

// Decrypt reads, decrypts, and writes data in chunks, verifying each chunk's authentication tag.
//
// Note: The buffer size is multiplied by 1024.
func Decrypt(aesGCM cipher.AEAD, bufferSize int, input io.Reader, output io.Writer) error {
	// Reads the IV (GCM_NONCE_LENGTH bytes) + encrypted data + tag (16 bytes)
	readBuffer := make([]byte, bufferSize*1024+GCM_TAG_SIZE)
	iv := make([]byte, GCM_NONCE_LENGTH)

	for {
		// Read IV for this chunk
		if _, err := io.ReadFull(input, iv); err != nil {
			if err == io.EOF {
				break
			}
			return fmt.Errorf("%w: %v", ErrIVReadFailed, err)
		}

		// Read encrypted data + tag
		n, err := input.Read(readBuffer)
		if err != nil && err != io.EOF {
			return fmt.Errorf("%w: %v", ErrReadFailed, err)
		}

		if n < GCM_TAG_SIZE {
			if n == 0 && err == io.EOF {
				break
			}
			return fmt.Errorf("%w: chunk too small to contain tag", ErrDecryptionFailed)
		}

		if err := decryptChunk(aesGCM, iv, readBuffer[:n], output); err != nil {
			return fmt.Errorf("%w: %v", ErrDecryptionFailed, err)
		}

		if err == io.EOF {
			break
		}
	}
	return nil
}

// Encrypts a chunk
func encryptChunk(aesGCM cipher.AEAD, iv []byte, buffer []byte, output io.Writer) error {
	// Encrypt and authenticate the chunk
	ciphertext := aesGCM.Seal(nil, iv, buffer, nil)

	// Write encrypted data with tag
	if _, err := output.Write(ciphertext); err != nil {
		return err
	}
	return nil
}

// Decrypts a chunk of data
func decryptChunk(aesGCM cipher.AEAD, iv []byte, buffer []byte, output io.Writer) error {
	plaintext, err := aesGCM.Open(nil, iv, buffer, nil)
	if err != nil {
		return err
	}

	// Write decrypted data
	if _, err := output.Write(plaintext); err != nil {
		return err
	}
	return nil
}

// WriteIV writes the initialization vector to the writer
func WriteIV(iv []byte, w io.Writer) error {
	if _, err := w.Write(iv); err != nil {
		return err
	}
	return nil
}

// ReadIV reads the initialization vector from the reader
func ReadIV(r io.Reader) ([]byte, error) {
	iv := make([]byte, GCM_NONCE_LENGTH)
	if _, err := io.ReadFull(r, iv); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrIVReadFailed, err)
	}
	return iv, nil
}
