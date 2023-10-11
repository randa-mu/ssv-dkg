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
	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(startCmd)
	rootCmd.AddCommand(keyCmd)

	rootCmd.PersistentFlags().StringVarP(&DirectoryFlag, "directory", "d", "~/.ssv", "directory to store node state")
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
