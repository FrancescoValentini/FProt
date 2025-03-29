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
	aesGCM, err := cipher.NewGCMWithNonceSize(block, 16)
	return aesGCM, err
}

// Encrypts a chunk of data
func encryptChunk(aesGCM cipher.AEAD, iv, chunk []byte, w io.Writer) error {
	ciphertext := aesGCM.Seal(nil, iv, chunk, nil)
	if _, err := w.Write(ciphertext); err != nil {
		return fmt.Errorf("%w: %v", ErrWriteFailed, err)
	}
	return nil
}

// Decrypts a chunk of data
func decryptChunk(aesGCM cipher.AEAD, iv, chunk []byte, w io.Writer) error {
	plaintext, err := aesGCM.Open(nil, iv, chunk, nil)
	if err != nil {
		return err
	}
	if _, err := w.Write(plaintext); err != nil {
		return fmt.Errorf("%w: %v", ErrWriteFailed, err)
	}
	return nil
}

func writeIV(iv []byte, w io.Writer) error {
	if _, err := w.Write(iv); err != nil {
		return err
	}
	return nil
}

func ReadIV(r io.Reader) ([]byte, error) {
	iv := make([]byte, 16)
	if _, err := io.ReadFull(r, iv); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrIVReadFailed, err)
	}
	return iv, nil
}
