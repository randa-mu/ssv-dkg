package cmd

import (
	"encoding/json"
	"fmt"
	"log"

	"github.com/randa-mu/ssv-dkg/shared/api"
	"github.com/randa-mu/ssv-dkg/shared/files"
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
		log.Fatal("you must pass the input flag with the output of the DKG you wish to create a keyfile for")
	}

	var ssvClient api.SsvClient
	if networkFlag == "mainnet" {
		ssvClient = api.MainnetSsvClient()
	} else if networkFlag == "holesky" {
		ssvClient = api.HoleskySsvClient()
	} else {
		log.Fatal("you must select a network to run against - holesky or mainnet")
	}

	s, err := files.LoadState(dkgStateFlag)
	if err != nil {
		log.Fatalf("error loading state: %v", err)
	}

	keyshareFile, err := files.CreateKeyshareFile(s.OwnerConfig, s.SigningOutput, ssvClient)
	if err != nil {
		log.Fatalf("error creating keyshare file: %v", err)
	}
	j, err := json.Marshal(keyshareFile)
	if err != nil {
		log.Fatalf("couldn't turn the keyshare into json: %v", err)
	}

	fmt.Println(string(j))
}
