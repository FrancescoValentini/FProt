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
package cmd

import (
	"fmt"
	"os"
	"time"

	"github.com/FrancescoValentini/FProt/common"
	"github.com/FrancescoValentini/FProt/cryptography"
	"github.com/FrancescoValentini/FProt/protocol"
	"github.com/spf13/cobra"
)

var encryptCmd = &cobra.Command{
	Use:   "encrypt",
	Short: "Encrypt data using AES",
	Long: `Encrypt data using AES
	
Example:
	fprot encrypt -p mypassword < input.txt > out.enc
`,
	Run: encrypt,
}

func init() {
	rootCmd.AddCommand(encryptCmd)

}

func encrypt(cmd *cobra.Command, args []string) {
	passwordFlag, _ := cmd.Flags().GetString("password")
	verboseFlag, _ := cmd.Flags().GetBool("verbose")

	recipientFlag, _ := cmd.Flags().GetStringArray("recipient")
	var entropy []byte
	var err error
	if passwordFlag == "" && len(recipientFlag) <= 0 {
		passwordFlag, err = common.ReadPasswordFromTTY(true)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Error:", err)
			os.Exit(1)
		}
	} else if passwordFlag != "" && len(recipientFlag) > 0 {
		fmt.Fprintln(os.Stderr, "Passwords and public keys cannot be mixed")
		os.Exit(1)
	}

	recipients := make([]protocol.Recipient, 0)

	if len(recipientFlag) != 0 {
		entropy, _ = cryptography.GenerateRandomBytes(32)
		for _, recipient := range recipientFlag {
			publicKey, err := common.LoadPublic(recipient)
			if err != nil {
				fmt.Fprintln(os.Stderr, "Error:", err)
				os.Exit(1)
			}
			recipient := protocol.PublicKeyRecipient(publicKey, entropy)
			recipients = append(recipients, recipient)
		}

	} else {
		var recipient protocol.Recipient
		recipient, entropy = protocol.PasswordRecipient(passwordFlag, verboseFlag)
		recipients = append(recipients, recipient)
	}
	start := time.Now()
	chunks := protocol.Encrypt(recipients, entropy, os.Stdin, os.Stdout)
	end := time.Since(start)
	if verboseFlag {
		fmt.Fprintf(os.Stderr, "Elapsed time: %v\n", end)
		fmt.Fprintf(os.Stderr, "Chunks: %v\n", chunks)
	}
}
