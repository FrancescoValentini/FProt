/*
Copyright © 2025 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// signCmd represents the sign command
var signCmd = &cobra.Command{
	Use:   "sign",
	Short: "Digitally sign data",
	Long: `Digitally sign data

Example:
	fprot sign -s myprivate.txt < input.txt > out.sig
	fprot sign -s myprivate.txt -armor< input.txt `,
	Run: sign,
}

func init() {
	rootCmd.AddCommand(signCmd)

	signCmd.PersistentFlags().StringP("priv-in", "s", "", "The private (secret) key")
	signCmd.PersistentFlags().BoolP("armor", "a", false, "If set the signature will be encoded in ascii")
}

func sign(cmd *cobra.Command, args []string) {
	fmt.Println("sign called")
}
