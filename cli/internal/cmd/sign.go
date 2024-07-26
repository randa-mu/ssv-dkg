package cmd

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/randa-mu/ssv-dkg/cli"
	"github.com/randa-mu/ssv-dkg/shared"
	"github.com/randa-mu/ssv-dkg/shared/api"
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
	// TODO: this should probably sign something more than just the deposit data root
	signingOutput, err := cli.Sign(shared.Uniq(append(args, operatorFlag...)), depositData, log)
	if err != nil {
		shared.Exit(fmt.Sprintf("%v", err))
	}

	path := cli.CreateFilename(stateDirectory, signingOutput)

	log.MaybeLog(fmt.Sprintf("✅ received signed deposit data! stored state in %s", path))
	log.Log(base64.StdEncoding.EncodeToString(signingOutput.GroupSignature))

	bytes, err := cli.StoreStateIfNotExists(path, signingOutput)
	if err != nil {
		log.Log(fmt.Sprintf("⚠️  there was an error storing the state; you should store it somewhere for resharing. Error: %v", err))
		log.Log(string(bytes))
	}
}

func verifyAndGetArgs(cmd *cobra.Command) ([]string, api.UnsignedDepositData, error) {
	// if the operator flag isn't passed, we consume operator addresses from stdin
	operators, err := arrayOrReader(operatorFlag, cmd.InOrStdin())
	if err != nil {
		return nil, api.UnsignedDepositData{}, errors.New("you must provider either the --operator flag or operators via stdin")
	}

	if inputPathFlag == "" {
		return nil, api.UnsignedDepositData{}, errors.New("input path cannot be empty")
	}

	// there is a default value, so this shouldn't really happen
	if stateDirectory == "" {
		return nil, api.UnsignedDepositData{}, errors.New("you must provide a state directory")
	}

	depositBytes, err := os.ReadFile(inputPathFlag)
	if err != nil {
		return nil, api.UnsignedDepositData{}, fmt.Errorf("error reading the deposit data file: %v", err)
	}

	var depositData api.UnsignedDepositData
	err = json.Unmarshal(depositBytes, &depositData)
	if err != nil {
		return nil, api.UnsignedDepositData{}, err
	}

	return operators, depositData, nil
}
