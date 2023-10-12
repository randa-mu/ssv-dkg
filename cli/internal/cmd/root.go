package cmd

import (
	"fmt"
	"github.com/spf13/cobra"
	"os"
)

var (
	rootCmd = &cobra.Command{
		Use:   "ssv-dkg",
		Short: "A CLI for creating distributed validators for Ethereum with SSV",
		Long:  "A CLI for creating distributed validators for Ethereum with SSV",
	}
)

func init() {
	rootCmd.AddCommand(versionCmd, createCmd, operatorsCmd)
}

func Execute() error {
	return rootCmd.Execute()
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version number of ssv-dkg",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println(VERSION)
	},
}

func exit(message string) {
	fmt.Println(message)
	os.Exit(1)
}
