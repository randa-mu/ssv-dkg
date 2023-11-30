package cmd

import (
	"encoding/base64"
	"fmt"
	"github.com/randa-mu/ssv-dkg/cli"
	"github.com/randa-mu/ssv-dkg/shared"
	"github.com/spf13/cobra"
	"io"
	"os"
	"strings"
)

var operatorFlag []string
var inputPathFlag string
var shortFlag bool
var stateDirectory string
var signCmd = &cobra.Command{
	Use:   "sign",
	Short: "Signs ETH deposit data by forming a validator cluster",
	Long:  "Signs ETH deposit data by forming a validator cluster that creates a distributed key.",
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
	// if the operator flag isn't passed, we consume them from stdin
	var args []string
	if len(operatorFlag) == 0 {
		stdin, err := io.ReadAll(cmd.InOrStdin())
		if err != nil {
			shared.Exit("error reading from stdin")
		}

		args = strings.Split(strings.Trim(string(stdin), "\n"), " ")
	}

	log := shared.QuietLogger{Quiet: shortFlag}

	if inputPathFlag == "" {
		shared.Exit("input path cannot be empty")
	}
	// read in the deposit data and unmarshal it from JSON
	depositData, err := os.ReadFile(inputPathFlag)
	if err != nil {
		shared.Exit(fmt.Sprintf("error reading the deposit data file: %v", err))
	}

	responses, err := cli.Sign(shared.Uniq(append(args, operatorFlag...)), depositData, log)
	if err != nil {
		shared.Exit(fmt.Sprintf("%v", err))
	}

	// we aggregate the partial signatures and write the final signed deposit data out
	// TODO: actually aggregate and verify the signature
	log.MaybeLog("✅ received signed deposit data!")
	log.Log(base64.StdEncoding.EncodeToString(responses[0].DepositDataPartialSignature))
}
