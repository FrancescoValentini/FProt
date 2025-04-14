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
	"github.com/spf13/cobra"
)

// keygenCmd represents the keygen command
var keygenCmd = &cobra.Command{
	Use:   "keygen",
	Short: "Generate ECC key pairs",
	Long: `Handle NIST P-384 ECC key pairs generation for asymmetric encryption.

This command can:
- Generate a new private + public key pair, or
- Derive a public key from an existing private key (with --priv-in).

If --priv-out/pub-out are not provided, keys are printed to stdout.

Note: When --priv-in is used, --priv-out is ignored (no new private key is generated).

Example:
	fprot keygen --priv-out prvkey.txt --pub-out pubkey.txt`,
	Run: keyGen,
}

func init() {
	rootCmd.AddCommand(keygenCmd)

	keygenCmd.PersistentFlags().StringP("priv-out", "", "", "Output file path for the private key")
	keygenCmd.PersistentFlags().StringP("pub-out", "", "", "Output file path for the public key")
	keygenCmd.PersistentFlags().StringP("priv-in", "", "", "The file where the private key is read")

}

func keyGen(cmd *cobra.Command, args []string) {

}
