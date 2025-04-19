/*
Copyright © 2025 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// verifyCmd represents the verify command
var verifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify a digital signature",
	Long: `Verify a digital signature

Example:
	fprot sign -s signature.txt < input.txt`,
	Run: verify,
}

func init() {
	rootCmd.AddCommand(verifyCmd)
	signCmd.PersistentFlags().StringP("signature", "s", "", "The digital signature")
}

func verify(cmd *cobra.Command, args []string) {
	fmt.Println("verify called")
}
