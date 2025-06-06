package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	golog "log"

	"github.com/randa-mu/ssv-dkg/shared/api"
	"github.com/randa-mu/ssv-dkg/shared/files"
	"github.com/spf13/cobra"

	"github.com/randa-mu/ssv-dkg/cli"
	"github.com/randa-mu/ssv-dkg/shared"
)

var (
	stateFilePath string
	reshareCmd    = &cobra.Command{
		Use:   "reshare",
		Short: "Reshares the key for a validator cluster you have already created",
		Long:  "Reshares the key for a validator cluster you have already created",
		Run:   Reshare,
	}
)

func init() {
	reshareCmd.PersistentFlags().StringArrayVarP(
		&operatorFlag,
		"operator",
		"o",
		nil,
		"SSV DKG node operators you wish to sign your ETH deposit data",
	)

	reshareCmd.PersistentFlags().StringVarP(
		&stateFilePath,
		"state",
		"s",
		"",
		"The filepath of the initial distributed key generated validator cluster that you wish to reshare. Note: this will get rewritten during execution.",
	)

	reshareCmd.PersistentFlags().StringVarP(
		&networkFlag,
		"network",
		"N",
		"mainnet",
		"mainnet, hoodi or holesky",
	)
}

func Reshare(cmd *cobra.Command, _ []string) {
	log := shared.QuietLogger{}
	if stateFilePath == "" {
		golog.Fatal("you must enter the path to the state created from the initial distributed key generation")
	}

	var ssvClient api.SsvClient
	if networkFlag == "mainnet" {
		ssvClient = api.MainnetSsvClient()
	} else if networkFlag == "holesky" {
		ssvClient = api.HoleskySsvClient()
	} else if networkFlag == "hoodi" {
		ssvClient = api.HoodiSsvClient()
	} else {
		golog.Fatal("network must be either mainnet, holesky or hoodi")
	}

	// if the operator flag isn't passed, we consume operator addresses from stdin
	operators, err := parseOperators(operatorFlag, cmd.InOrStdin())
	if err != nil {
		golog.Fatal("you must pass your new set of operators either via the operator flag or from stdin")
	}

	// load any existing state and run the reshare
	s, err := files.LoadState(stateFilePath)
	if err != nil {
		golog.Fatalf("❌ tried to load state from %s but it failed: %v", stateFilePath, err)
	}

	output, err := cli.Reshare(operators, s.SigningOutput, log)
	if err != nil {
		golog.Fatalf("❌ resharing failed: %v", err)
	}

	// store any state resulting from it
	nextState := files.StoredState{
		OwnerConfig:   s.OwnerConfig,
		SigningOutput: output,
	}
	bytes, err := files.StoreState(stateFilePath, nextState)
	if err != nil {
		fmt.Printf("⚠️  there was an error storing your state; printing it to the console so you can save it in a flat file. Err: %v\n", err)
		fmt.Println(string(bytes))
		os.Exit(1)
	} else {
		log.MaybeLog(fmt.Sprintf("✅ reshare completed successfully. Encrypted shares stored in %s", stateFilePath))
	}

	// we log an updated keyshare file so that users can register their new operators
	keyshareFile, err := files.CreateKeyshareFile(nextState.OwnerConfig, nextState.SigningOutput, ssvClient)
	if err != nil {
		golog.Fatalf("couldn't create keyshare file: %v", err)
	}

	j, err := json.Marshal(keyshareFile)
	if err != nil {
		golog.Fatalf("couldn't turn the keyshare into json: %v", err)
	}
	log.MaybeLog("📄 below is a keyfile JSON for use with the SSV UI:")
	log.Log(string(j))
}
