package cmd

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/randa-mu/ssv-dkg/cli"
	"github.com/randa-mu/ssv-dkg/shared"
	"github.com/randa-mu/ssv-dkg/shared/api"
)

var (
	operatorFlag       []string
	inputPathFlag      string
	shortFlag          bool
	stateDirectory     string
	validatorNonceFlag int32 = -1
	signCmd                  = &cobra.Command{
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

	signCmd.PersistentFlags().StringVarP(
		&inputPathFlag,
		"input",
		"i",
		"",
		"The filepath of the ETH deposit data",
	)
	signCmd.PersistentFlags().StringVarP(
		&stateDirectory,
		"output",
		"d",
		"~/.ssv",
		"Where you wish the CLI to store its state",
	)
	signCmd.PersistentFlags().BoolVarP(
		&shortFlag,
		"quiet",
		"q",
		false,
		"Only print out the signed deposit data",
	)
	signCmd.PersistentFlags().Int32VarP(
		&validatorNonceFlag,
		"validator-nonce",
		"n",
		-1, // default is -1 to ensure user MUST pass this flag (as -1 is invalid)
		"The current validator cluster nonce for the user from SSV contract. Be _very_ sure about this or you'll lose your stake",
	)
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

	if validatorNonceFlag < 0 {
		return nil, api.UnsignedDepositData{}, errors.New("you must pass a validator nonce retrieved from the SSV contract")
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
