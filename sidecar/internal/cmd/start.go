package cmd

import (
	"fmt"
	"github.com/spf13/cobra"
)

var startCmd = &cobra.Command{
	Use:   "start",
	Short: "Start the DKG sidecar",
	Long:  "Start the DKG sidecar daemon, enabling the creation of validator clusters using a distributed key.",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("nice sidecar")
	},
}
