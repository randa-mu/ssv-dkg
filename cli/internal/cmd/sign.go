package cmd

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path"
	"strings"

	"github.com/randa-mu/ssv-dkg/shared/crypto"
	"github.com/randa-mu/ssv-dkg/shared/files"
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
	networkFlag        string
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

	signCmd.PersistentFlags().StringVarP(
		&networkFlag,
		"network",
		"N",
		"mainnet",
		"mainnet, hoodi or holesky",
	)
}

func Sign(cmd *cobra.Command, _ []string) {
	signingConfig, err := parseArgs(cmd)
	if err != nil {
		log.Fatalf("%v", err)
	}

	suite := crypto.NewBLSSuite()
	// run a DKG and get the signed output
	logger := shared.QuietLogger{Quiet: shortFlag}
	signingOutput, err := cli.Sign(signingConfig, logger)
	if err != nil {
		log.Fatalf("%v", err)
	}

	statePath := files.CreateFilename(stateDirectoryFlag, signingOutput, files.StateFileName)
	depositDataPath := files.CreateFilename(stateDirectoryFlag, signingOutput, files.DepositDataFileName)
	keySharePath := files.CreateFilename(stateDirectoryFlag, signingOutput, files.KeyShareFileName)

	nextState := files.StoredState{OwnerConfig: signingConfig.Owner, SigningOutput: signingOutput}
	signedDepositData, err := files.CreateSignedDepositData(suite, signingConfig, signingOutput)
	if err != nil {
		log.Fatalf("couldn't create signed deposit data: %v", err)
	}
	keyShareFile, err := files.CreateKeyshareFile(nextState.OwnerConfig, nextState.SigningOutput, signingConfig.SsvClient)
	if err != nil {
		log.Fatalf("couldn't create keyshare file: %v", err)
	}

	errored := false
	bytes, err := files.StoreStateIfNotExists(statePath, nextState)
	if err != nil {
		errored = true
		logger.Log(fmt.Sprintf("⚠️  DKG was successful but there was an error storing the state; you should store it somewhere for resharing. Error: %v", err))
		logger.Log(string(bytes))
	}
	bytes, err = files.StoreStateIfNotExists(depositDataPath, signedDepositData)
	if err != nil {
		errored = true
		logger.Log(fmt.Sprintf("⚠️  DKG was successful but there was an error storing the deposit data; you should store it somewhere for resharing. Error: %v", err))
		logger.Log(string(bytes))
	}
	bytes, err = files.StoreStateIfNotExists(keySharePath, keyShareFile)
	if err != nil {
		errored = true
		logger.Log(fmt.Sprintf("⚠️  DKG was successful but there was an error storing the keyshares file; you should store it somewhere for resharing. Error: %v", err))
		logger.Log(string(bytes))
	}

	// we only want to say they've been stored if they all have
	if !errored {
		logger.Log(fmt.Sprintf("✅ your state, signed deposit data and keyshares files have been stored to %s", path.Join(stateDirectoryFlag, hex.EncodeToString(signingOutput.SessionID))))
	}
}

func parseArgs(cmd *cobra.Command) (api.SignatureConfig, error) {
	// if the operator flag isn't passed, we consume operator addresses from stdin
	operators, err := parseOperators(operatorFlag, cmd.InOrStdin())
	if err != nil {
		return api.SignatureConfig{}, fmt.Errorf("error parsing the operators: %v", err)
	}

	depositData, err := parseUnsignedInputData(inputPathFlag, stateDirectoryFlag)
	if err != nil {
		return api.SignatureConfig{}, fmt.Errorf("error parsing deposit data: %v", err)
	}

	ownerConfig, err := parseOwnerConfig(validatorNonceFlag, ethAddressFlag)
	if err != nil {
		return api.SignatureConfig{}, fmt.Errorf("error parsing owner details: %v", err)
	}

	var ssvClient api.SsvClient
	if networkFlag == "mainnet" {
		ssvClient = api.MainnetSsvClient()
	} else if networkFlag == "holesky" {
		ssvClient = api.HoleskySsvClient()
	} else if networkFlag == "hoodi" {
		ssvClient = api.HoodiSsvClient()
	} else {
		return api.SignatureConfig{}, fmt.Errorf("network must be either mainnet, hoodi or holesky")
	}

	return api.SignatureConfig{
		Operators:   operators,
		DepositData: depositData,
		Owner:       ownerConfig,
		SsvClient:   ssvClient,
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

	var depositData []api.UnsignedDepositData
	err = json.Unmarshal(depositBytes, &depositData)
	if err != nil {
		return api.UnsignedDepositData{}, err
	}

	return depositData[0], nil
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
