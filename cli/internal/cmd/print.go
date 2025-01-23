package cmd

import (
	"encoding/json"
	"fmt"

	"github.com/randa-mu/ssv-dkg/cli/state"
	"github.com/randa-mu/ssv-dkg/shared"
	"github.com/randa-mu/ssv-dkg/shared/api"
	"github.com/spf13/cobra"
)

var (
	dkgStateFlag string
	printCmd     = &cobra.Command{
		Use:   "print",
		Short: "prints out the key file required for registering a cluster",
		Long:  "prints out the key file required for registering a cluster in the SSV web UI",
		Run:   Print,
	}
)

func init() {
	printCmd.PersistentFlags().StringVarP(
		&dkgStateFlag,
		"input",
		"i",
		"",
		"The filepath of the DKG output data to print",
	)

	printCmd.PersistentFlags().StringVarP(
		&networkFlag,
		"network",
		"N",
		"mainnet",
		"mainnet or holesky",
	)
}

func Print(_ *cobra.Command, _ []string) {
	if dkgStateFlag == "" {
		shared.Exit("you must pass the input flag with the output of the DKG you wish to create a keyfile for")
	}

	var ssvClient api.SsvClient
	if networkFlag == "mainnet" {
		ssvClient = api.MainnetSsvClient()
	} else if networkFlag == "holesky" {
		ssvClient = api.HoleskySsvClient()
	} else {
		shared.Exit("you must select a network to run against - holesky or mainnet")
	}

	s, err := state.LoadState(dkgStateFlag)
	if err != nil {
		shared.Exit(fmt.Sprintf("error loading state: %v", err))
	}

	keyshareFile, err := state.CreateKeyshareFile(s.OwnerConfig, s.SigningOutput, ssvClient)
	if err != nil {
		shared.Exit(fmt.Sprintf("error creating keyshare file: %v", err))
	}
	j, err := json.Marshal(keyshareFile)
	if err != nil {
		shared.Exit(fmt.Sprintf("couldn't turn the keyshare into json: %v", err))
	}

	fmt.Println(string(j))
}
