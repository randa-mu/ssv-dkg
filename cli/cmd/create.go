package cmd

import (
	"fmt"
	"github.com/spf13/cobra"
)

var createCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a distributed validator",
	Long:  "Provide unsigned ETH deposit data, choose a cluster of validator nodes, trigger them to perform a distributed key generation and sign your deposit data, which you can then use to register your validator on the beacon chain",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("nice data")
	},
}
