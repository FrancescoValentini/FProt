package common

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"runtime"

	"github.com/FrancescoValentini/FProt/cryptography"
	"golang.org/x/term"
)

// ReadPasswordFromTTY securely reads a password from the terminal with confirmation.
// It operates directly on the TTY device, allowing it to work even when stdin/stdout are redirected.
// All prompts are written to os.Stderr to avoid interfering with piped output.
//
// Parameters:
//   - generatorEnabled: If true and the user provides an empty password,
//     a cryptographically secure random password will be generated and returned.
func ReadPasswordFromTTY(generatorEnabled bool) (string, error) {
	tty, err := openTTY()
	if err != nil {
		return "", err
	}
	defer tty.Close()

	fd := int(tty.Fd())

	if generatorEnabled {
		fmt.Fprint(os.Stderr, "Enter passphrase (Leave blank to generate one): ")
	} else {
		fmt.Fprint(os.Stderr, "Enter passphrase: ")
	}

	pass1, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}

	if len(pass1) == 0 {
		if generatorEnabled {
			rndData, _ := cryptography.GenerateRandomBytes(32)
			password := base64.RawURLEncoding.EncodeToString(rndData)
			fmt.Fprintf(os.Stderr, "Using generated password: %s", password)
			return base64.RawURLEncoding.EncodeToString(rndData), nil
		} else {
			return "", errors.New("no passphrase specified")
		}
	}

	fmt.Fprint(os.Stderr, "Confirm passphrase: ")
	pass2, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}

	if string(pass1) != string(pass2) {
		return "", errors.New("passphrases do not match")
	}

	return string(pass1), nil
}

// openTTY opens the system's terminal device for direct I/O operations.
// It provides cross-platform support for accessing the physical terminal
// independent of stdin/stdout redirection.
func openTTY() (*os.File, error) {
	if runtime.GOOS == "windows" {
		return os.OpenFile("CONIN$", os.O_RDWR, 0)
	}
	return os.OpenFile("/dev/tty", os.O_RDWR, 0)
}
