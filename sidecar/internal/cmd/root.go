package cmd

import (
	"fmt"
	"github.com/spf13/cobra"
)

var DirectoryFlag string

var rootCmd = &cobra.Command{
	Use:   "ssv-sidecar",
	Short: "A CLI for running a distributed validator sidecar for SSV",
	Long:  "A CLI for running a distributed validator sidecar for SSV",
}

func init() {
	rootCmd.AddCommand(versionCmd, startCmd, keyCmd)
	rootCmd.PersistentFlags().StringVarP(&DirectoryFlag, "directory", "d", "~/.ssv", "directory to store node state")

	startCmd.PersistentFlags().UintVarP(
		&PortFlag,
		"port",
		"p",
		8080,
		"the public port you wish to run the sidecar server on",
	)
}

func Execute() error {
	return rootCmd.Execute()
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version number of ssv-sidecar",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println(VERSION)
	},
}
