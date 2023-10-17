package cmd

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/randa-mu/ssv-dkg/shared"
	"github.com/randa-mu/ssv-dkg/shared/api"
	"github.com/randa-mu/ssv-dkg/shared/crypto"
	"github.com/spf13/cobra"
	"io"
	"net/http"
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

	if inputPathFlag == "" {
		shared.Exit("you must provide ETH deposit data to be signed")
	}

	// read in the deposit data and unmarshal it from JSON
	depositData, err := os.ReadFile(inputPathFlag)
	if err != nil {
		shared.Exit(fmt.Sprintf("error reading the deposit data file: %v", err))
	}
	data := api.SignRequest{
		Data: depositData,
	}
	requestJson, err := json.Marshal(data)
	if err != nil {
		shared.Exit("couldn't marshal deposit data to JSON")
	}

	// parse and validate the operators provided
	operators := shared.Uniq(append(args, operatorFlag...))
	numOfNodes := len(operators)
	if numOfNodes != 3 && numOfNodes != 5 && numOfNodes != 7 {
		shared.Exit("you must pass either 3, 5, or 7 operators to ensure a majority threshold")
	}

	log := shared.QuietLogger{Quiet: shortFlag}

	// let's first health-check everything
	log.MaybeLog("⏳ contacting nodes")
	for _, operator := range operators {
		res, err := http.Get(fmt.Sprintf("%s/health", operator))
		if err != nil {
			shared.Exit(fmt.Sprintf("☹️\tthere was an error health-checking %s: %v", operator, err))
		}
		if res.StatusCode != http.StatusOK {
			shared.Exit(fmt.Sprintf("☹️\tthere was an error health-checking %s: status %d", operator, res.StatusCode))
		}
	}

	// then let's actually kick off the DKG
	log.MaybeLog("⏳ starting distributed key generation")
	suite := crypto.NewBLSSuite()
	var responses []api.SignResponse
	for _, operator := range operators {

		// send the signing request to the node
		response, err := http.Post(fmt.Sprintf("%s/sign", operator), "application/json", bytes.NewBuffer(requestJson))
		if err != nil {
			shared.Exit(fmt.Sprintf("error creating cluster: %v", err))
		}
		if response.StatusCode != http.StatusOK {
			shared.Exit(fmt.Sprintf("error creation cluster. Node return status code %d", response.StatusCode))
		}

		// unmarshal the response as JSON
		responseBytes, err := io.ReadAll(response.Body)
		if err != nil {
			shared.Exit("error reading response bytes")
		}
		var signResponse api.SignResponse
		err = json.Unmarshal(responseBytes, &signResponse)
		if err != nil {
			shared.Exit(fmt.Sprintf("error unmarshalling json response: %v", err))
		}

		// verify that the signature over the deposit data verifies for the reported public key
		err = suite.Verify(depositData, signResponse.PublicKey, signResponse.Signature)
		if err != nil {
			shared.Exit(fmt.Sprintf("signature did not verify for the signed deposit data for node %s: %v", operator, err))
		}

		responses = append(responses, signResponse)
	}

	// we write the signed deposit data to stdout
	log.MaybeLog("✅ received signed deposit data!")
	log.Log(base64.StdEncoding.EncodeToString(responses[0].Signature))
}
