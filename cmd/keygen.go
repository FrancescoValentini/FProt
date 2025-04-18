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
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/rand"
	"fmt"
	"os"

	"github.com/FrancescoValentini/FProt/common"
	"github.com/FrancescoValentini/FProt/digitalsignature"
	"github.com/FrancescoValentini/FProt/ecies"
	"github.com/spf13/cobra"
)

// keygenCmd represents the keygen command
var keygenCmd = &cobra.Command{
	Use:   "keygen",
	Short: "Generate ECC key pairs",
	Long: `Handle NIST P-384 ECC key pairs generation for asymmetric encryption and digital signature.

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
	keygenCmd.PersistentFlags().BoolP("ecdsa", "", false, "If set generate ECDSA keys")

}

func keyGen(cmd *cobra.Command, args []string) {
	privOutFlag, _ := cmd.Flags().GetString("priv-out")
	pubOutFlag, _ := cmd.Flags().GetString("pub-out")
	privInFlag, _ := cmd.Flags().GetString("priv-in")
	ecdsaFlag, _ := cmd.Flags().GetBool("ecdsa")
	var encodedPrivate, encodedPublic, publicKeyID string
	if !ecdsaFlag {
		encodedPrivate, encodedPublic, publicKeyID = generateECDHKeys(privInFlag)
	} else {
		encodedPrivate, encodedPublic, publicKeyID = generateECDSAKeys(privInFlag)
	}

	printOrWriteKey(privOutFlag, encodedPrivate)
	if privOutFlag == "" {
		fmt.Fprintln(os.Stderr, "")
	}
	printOrWriteKey(pubOutFlag, encodedPublic)

	fmt.Fprintf(os.Stderr, "\nPublic Key ID: %s\n", publicKeyID)
}

func generateECDHKeys(privInFlag string) (string, string, string) {
	privateKey, err := getOrGeneratePrivateKey(privInFlag)
	if err != nil {
		exitWithError("", err)
	}

	encodedPrivate, encodedPublic := common.EncodeECDHKeys(privateKey)

	publicKeyID := ecies.GetPublicKeyID(privateKey.PublicKey().Bytes())

	return encodedPrivate, encodedPublic, publicKeyID
}

func generateECDSAKeys(privInFlag string) (string, string, string) {
	privateKey, err := getOrGenerateECDSAPrivateKey(privInFlag)
	if err != nil {
		exitWithError("", err)
	}

	encodedPrivate, encodedPublic, err := common.EncodeECDSAKeys(privateKey)
	if err != nil {
		exitWithError("", err)
	}
	pubBytes, err := digitalsignature.PublicKeyToBytes(&privateKey.PublicKey)
	if err != nil {
		exitWithError("", err)
	}
	publicKeyID := ecies.GetPublicKeyID(pubBytes)

	return encodedPrivate, encodedPublic, publicKeyID
}

// Loads an existing private key from the provided flag value
// or generates a new ECDH private key if no input is provided.
func getOrGeneratePrivateKey(privInFlag string) (*ecdh.PrivateKey, error) {
	if privInFlag != "" {
		rawKey, err := common.LoadPrivate(privInFlag)
		if err != nil {
			return nil, err
		}
		return ecies.LoadPrivateKey(rawKey)
	}
	return ecies.GeneratePrivateKey(rand.Reader)
}

// Loads an existing private key from the provided flag value
// or generates a new ECDSA private key if no input is provided.
func getOrGenerateECDSAPrivateKey(privInFlag string) (*ecdsa.PrivateKey, error) {
	if privInFlag != "" {
		rawKey, err := common.LoadECDSAPrivate(privInFlag)
		if err != nil {
			return nil, err
		}
		return digitalsignature.PrivateKeyFromBytes(rawKey)
	}
	return digitalsignature.GeneratePrivateKey(rand.Reader)
}

// Prints the data to stderr or writes it to a file,
func printOrWriteKey(outputFlag, data string) {
	if outputFlag != "" {
		if err := common.WriteFileIfNotExists(outputFlag, data); err != nil {
			exitWithError("", err)
		}
	} else {
		fmt.Fprintln(os.Stderr, data)
	}
}

// Prints an error message to stderr and exits the program with status code 1
func exitWithError(msg string, err error) {
	fmt.Fprintln(os.Stderr, msg, err)
	os.Exit(1)
}
