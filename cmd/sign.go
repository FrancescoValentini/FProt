/*
Copyright © 2025 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"crypto/ecdsa"
	"fmt"
	"os"

	"github.com/FrancescoValentini/FProt/common"
	"github.com/FrancescoValentini/FProt/cryptography"
	"github.com/FrancescoValentini/FProt/digitalsignature"
	"github.com/spf13/cobra"
)

// signCmd represents the sign command
var signCmd = &cobra.Command{
	Use:   "sign",
	Short: "Digitally sign data",
	Long: `Digitally sign data

Example:
	fprot sign -s myprivate.txt < input.txt > out.sig
	fprot sign -s myprivate.txt -armor < input.txt `,
	Run: sign,
}

func init() {
	rootCmd.AddCommand(signCmd)

	signCmd.PersistentFlags().BoolP("armor", "a", false, "If set the signature will be encoded in ascii")
}

func sign(cmd *cobra.Command, args []string) {
	privateKeyFlag, _ := cmd.Flags().GetString("priv-in")
	armorFlag, _ := cmd.Flags().GetBool("armor")

	privateKey, err := getPrivateKey(privateKeyFlag)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error while loading private key: ", err)
		os.Exit(1)
	}

	signature, err := digitalsignature.Sign(privateKey, cryptography.BUFFER_SIZE, os.Stdin)

	if err != nil {
		fmt.Fprintln(os.Stderr, "Error while signing: ", err)
		os.Exit(1)
	}

	if !armorFlag {
		os.Stdout.Write(signature)
	} else {
		armored := common.EncodeArmor(signature)
		os.Stdout.Write([]byte(armored))
	}

}

func getPrivateKey(privInFlag string) (*ecdsa.PrivateKey, error) {
	rawKey, err := common.LoadECDSAPrivate(privInFlag)
	if err != nil {
		return nil, err
	}
	return digitalsignature.PrivateKeyFromBytes(rawKey)
}
