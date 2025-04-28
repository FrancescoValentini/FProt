// This package provides all the needed methods, constants and errors to work
// with ECDSA digital signatures
package digitalsignature

const ( // BYTES
	TimestampSize   = 8
	PublicKeySize   = 120
	PublicKeyIDSize = 20
	ContentHashSize = 48
	SignedInfoSize  = TimestampSize + PublicKeySize + PublicKeyIDSize + ContentHashSize
)
