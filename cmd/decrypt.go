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
	"io"
	"os"
	"time"

	"github.com/FrancescoValentini/FProt/common"
	"github.com/FrancescoValentini/FProt/protocol"
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
	passwordFlag, _ := cmd.Flags().GetString("password")
	verboseFlag, _ := cmd.Flags().GetBool("verbose")
	privateKeyFlag, _ := cmd.Flags().GetString("priv-in")
	var entropy []byte
	var reader io.Reader

	common.CheckCLIArgsDecrypt(passwordFlag, privateKeyFlag, false)

	start := time.Now()
	if privateKeyFlag != "" {
		privateKey, err := common.LoadPrivate(privateKeyFlag)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Error:", err)
			os.Exit(1)
		}
		entropy, reader = protocol.RecoverPublicKeyEntropy(privateKey, os.Stdin)
	} else {
		entropy, reader = protocol.RecoverPasswordEntropy(passwordFlag, verboseFlag, os.Stdin)
	}

	chunks := protocol.Decrypt(entropy, reader, os.Stdout)
	end := time.Since(start)
	if verboseFlag {
		fmt.Fprintf(os.Stderr, "Elapsed time: %v\n", end)
		fmt.Fprintf(os.Stderr, "Chunks: %v\n", chunks)
	}
}
