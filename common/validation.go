package common

import (
	"fmt"
	"os"
)

func CheckCLIArgsEncrypt(password string, recipients []string) {
	if password == "" && len(recipients) <= 0 {
		fmt.Fprintln(os.Stderr, "Specify a password or public key")
		os.Exit(1)
	} else if password != "" && len(recipients) > 0 {
		fmt.Fprintln(os.Stderr, "Passwords and public keys cannot be mixed")
		os.Exit(1)
	}
}

func CheckCLIArgsDecrypt(password string, privateKey string, mode bool) {
	if password == "" && privateKey == "" {
		fmt.Fprintln(os.Stderr, "Specify a password or private key")
		os.Exit(1)
	} else if password != "" && privateKey != "" {
		fmt.Fprintln(os.Stderr, "Passwords and private keys cannot be mixed")
		os.Exit(1)
	}
}
