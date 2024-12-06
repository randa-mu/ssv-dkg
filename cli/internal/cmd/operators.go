package cmd

import (
	"github.com/spf13/cobra"
)

var (
	sourceUrlFlag  string
	sourceFileFlag string
	operatorsCmd   = &cobra.Command{
		Use:   "operators",
		Short: "Commands relating to SSV node operators",
	}
)

func init() {
	operatorsCmd.AddCommand(operatorsListCmd)
	operatorsCmd.PersistentFlags().StringVarP(
		&sourceUrlFlag,
		"source-url",
		"u",
		"https://raw.githubusercontent.com/randa-mu/ssv-dkg/master/nodes/operators.json",
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
