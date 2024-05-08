package cmd

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/randa-mu/ssv-dkg/cli"
	"github.com/randa-mu/ssv-dkg/shared"
	"github.com/spf13/cobra"
)

var operatorFlag []string
var inputPathFlag string
var shortFlag bool
var stateDirectory string
var signCmd = &cobra.Command{
	Use:   "sign",
	Short: "Signs ETH deposit data by forming a validator cluster",
	Long:  "Signs ETH deposit data by forming a validator cluster that creates a distributed key. Operators can be passed via stdin.",
	Run:   Sign,
}

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

	log.MaybeLog("✅ received signed deposit data!")
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
	var args []string
	if len(operatorFlag) == 0 {
		stdin, err := io.ReadAll(cmd.InOrStdin())
		if err != nil {
			return nil, nil, errors.New("error reading from stdin")
		}

		operatorString := strings.Trim(string(stdin), "\n")
		if operatorString == "" {
			return nil, nil, errors.New("you must provider either the --operator flag or operators via stdin")
		}

		args = strings.Split(operatorString, " ")
	} else {
		args = operatorFlag
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

	return args, depositData, nil
}
