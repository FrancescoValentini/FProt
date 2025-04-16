package common

import "errors"

// Encoding errors
var (
	ErrInvalidBase64           = errors.New("failed to decode base64")
	ErrInvalidPublicKeyFormat  = errors.New("invalid public key format")
	ErrInvalidPrivateKeyFormat = errors.New("invalid private key format")
)

// Files errors
var (
	ErrInvalidPath  = errors.New("invalid path")
	ErrIsFolder     = errors.New("the path is a folder")
	ErrReadingFile  = errors.New("failed to read file")
	ErrWritingFile  = errors.New("failed to write file")
	ErrFileExist    = errors.New("the file already exists")
	ErrFileNotExist = errors.New("the file does not exist")
)
