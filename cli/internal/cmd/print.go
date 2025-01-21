package cmd

import (
	"encoding/json"
	"fmt"

	"github.com/randa-mu/ssv-dkg/cli/internal/state"
	"github.com/randa-mu/ssv-dkg/shared"
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
}

func Print(_ *cobra.Command, _ []string) {
	if dkgStateFlag == "" {
		shared.Exit("you must pass the input flag with the output of the DKG you wish to create a keyfile for")
	}

	s, err := state.LoadState(dkgStateFlag)
	if err != nil {
		shared.Exit(fmt.Sprintf("error loading state: %v", err))
	}

	keyshareFile, err := state.CreateKeyshareFile(s.OwnerConfig, s.SigningOutput)
	if err != nil {
		shared.Exit(fmt.Sprintf("error creating keyshare file: %v", err))
	}
	j, err := json.Marshal(keyshareFile)
	if err != nil {
		shared.Exit(fmt.Sprintf("couldn't turn the keyshare into json: %v", err))
	}

	fmt.Println(string(j))
}
