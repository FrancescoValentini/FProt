/*
Copyright © 2025 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// deriveCmd represents the derive command
var deriveCmd = &cobra.Command{
	Use:   "derive",
	Short: "Derive the 256-bit key from the password",
	Long: `This command allows you to display the key that is derived from the 
specified password and nonce using the Argon2id KDF.
The password must be defined with the -p option, using the -k option has 
no effect on this command.

Example:
	fprot derive -p password -n C9519B2C5F452E79A8883926ADBE53C2
`,

	Run: derive,
}

func init() {
	rootCmd.AddCommand(deriveCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// deriveCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// deriveCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
	rootCmd.PersistentFlags().StringP("nonce", "n", "", "The Argon2id nonce (hex format)")

}

func derive(cmd *cobra.Command, args []string) {
	passwordFlag, _ := cmd.Flags().GetString("password")

	if passwordFlag == "" {
		fmt.Fprintf(os.Stderr, "Password must be specified with the -p flag")
		os.Exit(1)
	}

}
