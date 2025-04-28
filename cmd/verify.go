/*
Copyright © 2025 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"encoding/base64"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/FrancescoValentini/FProt/common"
	"github.com/FrancescoValentini/FProt/cryptography"
	"github.com/FrancescoValentini/FProt/digitalsignature"
	"github.com/FrancescoValentini/FProt/ecies"
	"github.com/spf13/cobra"
)

// verifyCmd represents the verify command
var verifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify a digital signature",
	Long: `Verify a digital signature

Example:
	fprot verify --sig signature.txt < input.txt`,
	Run: verify,
}

func init() {
	rootCmd.AddCommand(verifyCmd)
	verifyCmd.PersistentFlags().StringP("sig", "", "", "The digital signature")
	verifyCmd.PersistentFlags().BoolP("armor", "a", false, "If set the signature will be encoded in ascii")

}

func verify(cmd *cobra.Command, args []string) {
	signatureFlag, _ := cmd.Flags().GetString("sig")
	armorFlag, _ := cmd.Flags().GetBool("armor")
	var sig []byte
	var err error

	if armorFlag {
		sig, err = decodeSignature(signatureFlag)
		fmt.Fprintf(os.Stderr, "%s\n", signatureFlag)
	} else {
		sig, err = common.ReadFileBytes(signatureFlag)
	}

	if err != nil {
		fmt.Fprintln(os.Stderr, "Error while reading signature: ", err)
		os.Exit(1)
	}

	valid, info, error := digitalsignature.Verify(sig, cryptography.BUFFER_SIZE, os.Stdin)
	if error != nil {
		fmt.Fprintln(os.Stderr, "Invalid Signature Error:\n", err)
		os.Exit(1)
	}

	if valid {
		printInfo(info)
	}
}

func printInfo(info digitalsignature.SignedInfo) {
	hash := base64.RawURLEncoding.EncodeToString(info.ContentHash[:])
	pubId := ecies.GetPublicKeyID(info.PublicKey[:])

	fmt.Fprintf(os.Stderr, "SIGNATURE OK\n")
	fmt.Fprintf(os.Stderr, "Data hash: %s\n", hash)
	fmt.Fprintf(os.Stderr, "Public key ID: %s\n", pubId)
	fmt.Fprintf(os.Stderr, "Timestamp: %s\n", info.Timestamp.Format(time.RFC3339))
}

func decodeSignature(signature string) ([]byte, error) {
	var sig []byte
	var err error
	if strings.Contains(signature, common.SIGNATURE_HEADER) {
		sig, err = common.DecodeArmor(signature)
		if err != nil {
			return nil, err
		}
		return sig, nil
	}
	return nil, err
}
