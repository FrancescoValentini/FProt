// This package contains the protocol for encrypted data
package protocol

import "errors"

const HMAC_KEY_KDFINFO = "fprot-header-hmac"
const FILE_KEY_KDFINFO = "fprot-file-key"

// Errors
var (
	ErrInvalidHeader = errors.New("invalid header")
	ErrMissingHMAC   = errors.New("missing HMAC")

	ErrHmacVerify              = errors.New("unable to verify HMAC")
	ErrHmacOrNoMatchingPrivate = errors.New("unable to verify HMAC or no matching private key, the private key does not match the expected recipient list")
)

// Data structure representing a recipient
type Recipient struct {
	Type string
	Args []string
	Body []byte
}

// Data structure representing the header of encrypted data
type FprotHeader struct {
	Version    string
	Recipients []Recipient
	HeaderMac  []byte
}
