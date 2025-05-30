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
	"github.com/spf13/cobra"
)

// decryptCmd represents the decrypt command
var decryptCmd = &cobra.Command{
	Use:   "decrypt",
	Short: "Decrypt data using AES",
	Long: `Decrypt data using AES

Example:
	fprot decrypt -p mypassword < input.txt > out.enc
`,
	Run: decrypt,
}

func init() {
	rootCmd.AddCommand(decryptCmd)

}

func decrypt(cmd *cobra.Command, args []string) {
	keyFlag, _ := cmd.Flags().GetString("key")
	passwordFlag, _ := cmd.Flags().GetString("password")
	verboseFlag, _ := cmd.Flags().GetBool("verbose")
	privateKeyFlag, _ := cmd.Flags().GetString("priv-in")
	var key []byte

	if privateKeyFlag != "" {
		key = common.DecryptAsymmetricKey(privateKeyFlag, os.Stdin)
	} else {
		key = common.SymmetricKey(keyFlag, passwordFlag, verboseFlag, true)
	}

	aesGCM, err := cryptography.GetAESGCM(key)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error creating GCM:", err)
		os.Exit(1)
	}
	start := time.Now()
	chunks, err := cryptography.Decrypt(aesGCM, cryptography.BUFFER_SIZE, os.Stdin, os.Stdout)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Decryption failed: %v\n", err)
		os.Exit(1)
	}
	end := time.Since(start)
	if verboseFlag {
		fmt.Fprintf(os.Stderr, "Elapsed time: %v\n", end)
		fmt.Fprintf(os.Stderr, "Chunks: %v\n", chunks)
	}
}
