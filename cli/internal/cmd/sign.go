package cmd

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/randa-mu/ssv-dkg/cli/internal/state"
	"github.com/spf13/cobra"

	"github.com/randa-mu/ssv-dkg/cli"
	"github.com/randa-mu/ssv-dkg/shared"
	"github.com/randa-mu/ssv-dkg/shared/api"
)

var (
	operatorFlag       []string
	inputPathFlag      string
	shortFlag          bool
	stateDirectoryFlag string
	validatorNonceFlag int32 = -1
	ethAddressFlag     string
	signCmd            = &cobra.Command{
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
		"deposit-file",
		"f",
		"",
		"The filepath of the ETH deposit data",
	)
	signCmd.PersistentFlags().StringVarP(
		&stateDirectoryFlag,
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
	signCmd.PersistentFlags().StringVarP(
		&ethAddressFlag,
		"owner-address",
		"a",
		"",
		"The ETH address of the user creating the cluster in hex format",
	)
}

func Sign(cmd *cobra.Command, _ []string) {
	signingConfig, err := parseArgs(cmd)
	if err != nil {
		shared.Exit(fmt.Sprintf("%v", err))
	}

	// run a DKG and get the signed output
	log := shared.QuietLogger{Quiet: shortFlag}
	signingOutput, err := cli.Sign(signingConfig, log)
	if err != nil {
		shared.Exit(fmt.Sprintf("%v", err))
	}

	path := state.CreateFilename(stateDirectoryFlag, signingOutput)

	nextState := state.StoredState{
		OwnerConfig:   signingConfig.Owner,
		SigningOutput: signingOutput,
	}
	bytes, err := state.StoreStateIfNotExists(path, nextState)
	if err != nil {
		log.Log(fmt.Sprintf("⚠️  DKG was successful but there was an error storing the state; you should store it somewhere for resharing. Error: %v", err))
		log.Log(string(bytes))
	} else {
		log.MaybeLog(fmt.Sprintf("✅ received signed deposit data! stored state in %s", path))
	}

	keyshareFile, err := state.CreateKeyshareFile(nextState.OwnerConfig, nextState.SigningOutput)
	if err != nil {
		shared.Exit(fmt.Sprintf("couldn't create keyshare file: %v", err))
	}

	j, err := json.Marshal(keyshareFile)
	if err != nil {
		shared.Exit(fmt.Sprintf("couldn't turn the keyshare into json: %v", err))
	}
	log.MaybeLog("📄 below is a keyfile JSON for use with the SSV UI:")
	log.Log(string(j))
}

func parseArgs(cmd *cobra.Command) (cli.SignatureConfig, error) {
	// if the operator flag isn't passed, we consume operator addresses from stdin
	operators, err := parseOperators(operatorFlag, cmd.InOrStdin())
	if err != nil {
		return cli.SignatureConfig{}, fmt.Errorf("error parsing the operators: %v", err)
	}

	depositData, err := parseUnsignedInputData(inputPathFlag, stateDirectoryFlag)
	if err != nil {
		return cli.SignatureConfig{}, fmt.Errorf("error parsing deposit data: %v", err)
	}

	ownerConfig, err := parseOwnerConfig(validatorNonceFlag, ethAddressFlag)
	if err != nil {
		return cli.SignatureConfig{}, fmt.Errorf("error parsing owner details: %v", err)
	}

	return cli.SignatureConfig{
		Operators:   operators,
		DepositData: depositData,
		Owner:       ownerConfig,
	}, nil
}

// parseOperators returns the array if it's non-empty, or reads an array of strings from the provided `Reader` if it's empty
func parseOperators(arr []string, r io.Reader) ([]string, error) {
	if len(arr) != 0 {
		return arr, nil
	}

	bytes, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	lines := strings.Trim(string(bytes), "\n")
	if lines == "" {
		return nil, errors.New("reader was empty")
	}

	return shared.Uniq(strings.Split(lines, " ")), nil
}

func parseUnsignedInputData(inputPathFlag string, stateDirectory string) (api.UnsignedDepositData, error) {
	if inputPathFlag == "" {
		return api.UnsignedDepositData{}, errors.New("input path cannot be empty")
	}

	// there is a default value, so this shouldn't really happen
	if stateDirectory == "" {
		return api.UnsignedDepositData{}, errors.New("you must provide a state directory")
	}

	depositBytes, err := os.ReadFile(inputPathFlag)
	if err != nil {
		return api.UnsignedDepositData{}, fmt.Errorf("error reading the deposit data file: %v", err)
	}

	var depositData api.UnsignedDepositData
	err = json.Unmarshal(depositBytes, &depositData)
	if err != nil {
		return api.UnsignedDepositData{}, err
	}

	return depositData, nil
}

func parseOwnerConfig(validatorNonce int32, ethAddress string) (api.OwnerConfig, error) {
	if validatorNonce < 0 {
		return api.OwnerConfig{}, fmt.Errorf("validator nonce must be set")
	}

	// remove any preceding `0x` before parsing it
	cleanAddress := strings.Trim(ethAddress, "0x")
	if cleanAddress == "" {
		return api.OwnerConfig{}, fmt.Errorf("owner address cannot be empty")
	}

	address, err := hex.DecodeString(cleanAddress)
	if err != nil {
		return api.OwnerConfig{}, fmt.Errorf("owner address must be valid hex: %v", err)
	}

	return api.OwnerConfig{
		Address:        address,
		ValidatorNonce: uint32(validatorNonce),
	}, nil
}
