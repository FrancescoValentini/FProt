package digitalsignature

import (
	"crypto/sha512"
	"fmt"
	"io"
)

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
