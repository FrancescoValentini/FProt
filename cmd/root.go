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
	"os"

	"github.com/spf13/cobra"
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "FProt",
	Short: "Command-line utility for securely encrypting and decrypting data",
	Long: `FProt is a command-line utility for securely encrypting and decrypting data using the AES-256-GCM.  

FProt operates as a stream processor, reading from stdin and writing to stdout, 
making it easy to integrate into pipelines and scripts.

Examples  
- fprot encrypt -p mypassword < plain.txt > cipher.fprot
- fprot decrypt -p mypassword < cipher.fprot > plain.txt

Author: Francesco Valentini`,
	// Uncomment the following line if your bare application
	// has an action associated with it:
	// Run: func(cmd *cobra.Command, args []string) { },

	Run: func(cmd *cobra.Command, args []string) {
		// Checks if stdin is redirected (i.e. not a terminal)
		stdinStat, _ := os.Stdin.Stat()
		isInputFromPipe := (stdinStat.Mode() & os.ModeCharDevice) == 0

		if isInputFromPipe {
			// Execute the encrypt command
			encryptCmd.Run(cmd, args)
		} else {
			// show help command
			_ = cmd.Help()
		}
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().StringP("password", "p", "", "The password used to derive the 256 bit key")
	rootCmd.PersistentFlags().StringP("recipient", "r", "", "The recipient public key")
	rootCmd.PersistentFlags().StringP("key", "k", "", "The raw 256 bit key (hex format)")
	rootCmd.PersistentFlags().BoolP("verbose", "v", false, "Verbose mode")
}
