package cmd

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/randa-mu/ssv-dkg/cli"
	"github.com/randa-mu/ssv-dkg/shared"
)

var (
	operatorFlag   []string
	inputPathFlag  string
	shortFlag      bool
	stateDirectory string
	signCmd        = &cobra.Command{
		Use:   "sign",
		Short: "Signs ETH deposit data by forming a validator cluster",
		Long:  "Signs ETH deposit data by forming a validator cluster that creates a distributed key. Operators can be passed via stdin.",
		Run:   Sign,
	}
)

func init() {
	signCmd.PersistentFlags().StringArrayVarP(
		&operatorFlag,
		"operator",
		"o",
		nil,
		"SSV DKG node operators you wish to sign your ETH deposit data",
	)

	signCmd.PersistentFlags().StringVarP(&inputPathFlag, "input", "i", "", "The filepath of the ETH deposit data")
	signCmd.PersistentFlags().StringVarP(&stateDirectory, "output", "d", "~/.ssv", "Where you wish the CLI to store its state")
	signCmd.PersistentFlags().BoolVarP(&shortFlag, "quiet", "q", false, "Only print out the signed deposit data")
}

func Sign(cmd *cobra.Command, _ []string) {
	args, depositData, err := verifyAndGetArgs(cmd)
	if err != nil {
		shared.Exit(fmt.Sprintf("%v", err))
	}

	log := shared.QuietLogger{Quiet: shortFlag}
	signingOutput, err := cli.Sign(shared.Uniq(append(args, operatorFlag...)), depositData, log)
	if err != nil {
		shared.Exit(fmt.Sprintf("%v", err))
	}

	log.MaybeLog(fmt.Sprintf("✅ received signed deposit data! sessionID: %s", hex.EncodeToString(signingOutput.SessionID)))
	log.Log(base64.StdEncoding.EncodeToString(signingOutput.GroupSignature))

	path := cli.CreateFilename(stateDirectory, signingOutput)
	bytes, err := cli.StoreStateIfNotExists(path, signingOutput)
	if err != nil {
		log.Log(fmt.Sprintf("⚠️  there was an error storing the state; you should store it somewhere for resharing. Error: %v", err))
		log.Log(string(bytes))
	}
}

func verifyAndGetArgs(cmd *cobra.Command) ([]string, []byte, error) {
	// if the operator flag isn't passed, we consume operator addresses from stdin
	operators, err := arrayOrReader(operatorFlag, cmd.InOrStdin())
	if err != nil {
		return nil, nil, errors.New("you must provider either the --operator flag or operators via stdin")
	}

	if inputPathFlag == "" {
		return nil, nil, errors.New("input path cannot be empty")
	}

	// there is a default value, so this shouldn't really happen
	if stateDirectory == "" {
		return nil, nil, errors.New("you must provide a state directory")
	}

	depositData, err := os.ReadFile(inputPathFlag)
	if err != nil {
		return nil, nil, fmt.Errorf("error reading the deposit data file: %v", err)
	}

	return operators, depositData, nil
}
