package cmd

import (
	"github.com/spf13/cobra"
)

var sourceUrlFlag = "https://raw.githubusercontent.com/randa-mu/ssv-dkg/master/nodes/operators.json"
var sourceFileFlag string
var operatorsCmd = &cobra.Command{
	Use:   "operators",
	Short: "Commands relating to SSV node operators",
}

func init() {
	operatorsCmd.AddCommand(operatorsListCmd)
	operatorsCmd.PersistentFlags().StringVarP(
		&sourceUrlFlag,
		"source-url",
		"u",
		"https://github.com/randa-mu/ssv-dkg/blob/master/nodes/operators.toml",
		"The location of a toml file listing operators and their signed public keys",
	)
	operatorsCmd.PersistentFlags().StringVarP(
		&sourceFileFlag,
		"source-file",
		"f",
		"",
		"A local toml file listing operators and their signed public keys",
	)
}
