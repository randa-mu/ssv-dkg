package cmd

import (
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/randa-mu/ssv-dkg/cli"
	"github.com/randa-mu/ssv-dkg/shared"
	"github.com/spf13/cobra"
)

var stateFilePath string
var reshareCmd = &cobra.Command{
	Use:   "reshare",
	Short: "Reshares the key for a validator cluster you have already created",
	Long:  "Reshares the key for a validator cluster you have already created",
	Run:   Reshare,
}

func init() {
	reshareCmd.PersistentFlags().StringArrayVarP(
		&operatorFlag,
		"operator",
		"o",
		nil,
		"SSV DKG node operators you wish to sign your ETH deposit data",
	)
	reshareCmd.PersistentFlags().StringVarP(&stateFilePath,
		"state",
		"s",
		"",
		"The filepath of the initial distributed key generated validator cluster that you wish to reshare. Note: this will get rewritten during execution.",
	)
}

func Reshare(cmd *cobra.Command, _ []string) {
	log := shared.QuietLogger{}
	if stateFilePath == "" {
		shared.Exit("you must enter the path to the state created from the initial distributed key generation")
	}

	// if the operator flag isn't passed, we consume operator addresses from stdin
	operators, err := operatorsOrStdin(cmd)
	if err != nil {
		shared.Exit("you must pass your new set of operators either via the operator flag or from stdin")
	}

	state, err := cli.LoadState(stateFilePath)
	if err != nil {
		shared.Exit(fmt.Sprintf("❌ tried to load state from %s but it failed: %v", stateFilePath, err))
	}

	nextState, err := cli.Reshare(operators, state, log)
	if err != nil {
		shared.Exit(fmt.Sprintf("❌ resharing failed: %v", err))
	}

	bytes, err := cli.StoreState(stateFilePath, nextState)
	if err != nil {
		fmt.Printf("⚠️  there was an error storing your state; printing it to the console so you can save it in a flat file. Err: %v\n", err)
		fmt.Println(string(bytes))
		shared.Exit("")
	}

	log.MaybeLog(fmt.Sprintf("✅ reshare completed successfully. Encrypted shares stored in %s", stateFilePath))
}

func operatorsOrStdin(cmd *cobra.Command) ([]string, error) {
	if len(operatorFlag) != 0 {
		return operatorFlag, nil
	}
	// if the operator flag isn't passed, we consume operator addresses from stdin
	stdin, err := io.ReadAll(cmd.InOrStdin())
	if err != nil {
		return nil, errors.New("error reading from stdin")
	}

	operatorString := strings.Trim(string(stdin), "\n")
	if operatorString == "" {
		return nil, errors.New("you must provider either the --operator flag or operators via stdin")
	}

	return strings.Split(operatorString, " "), nil
}
