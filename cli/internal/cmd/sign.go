package cmd

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/randa-mu/ssv-dkg/shared"
	"github.com/randa-mu/ssv-dkg/shared/api"
	"github.com/spf13/cobra"
	"io"
	"net/http"
	"os"
	"strings"
)

var operatorFlag []string
var inputPathFlag string
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
}

func Sign(cmd *cobra.Command, _ []string) {
	stdin, err := io.ReadAll(cmd.InOrStdin())
	if err != nil {
		shared.Exit("error reading from stdin")
	}

	args := strings.Split(strings.Trim(string(stdin), "\n"), " ")

	if inputPathFlag == "" {
		shared.Exit("you must provide ETH deposit data to be signed")
	}

	contents, err := os.ReadFile(inputPathFlag)
	if err != nil {
		shared.Exit(fmt.Sprintf("error reading the deposit data file: %v", err))
	}
	data := api.SignRequest{
		Data: contents,
	}
	requestJson, err := json.Marshal(data)
	if err != nil {
		shared.Exit("couldn't marshal deposit data to JSON")
	}

	operators := shared.Uniq(append(args, operatorFlag...))
	// let's turn this check off for testing :)
	//if len(operators)%3 != 0 && len(operators)%5 != 0 && len(operators)%7 != 0 {
	//	shared.Exit("you must pass either 3, 5, or 7 operators to ensure a majority threshold")
	//}

	// let's first health-check everything
	fmt.Println("⏳ contacting nodes")
	for _, operator := range operators {
		res, err := http.Get(fmt.Sprintf("%s/health", operator))
		if err != nil {
			shared.Exit(fmt.Sprintf("☹️\tthere was an error healthchecking %s: %v", operator, err))
		}
		if res.StatusCode != http.StatusOK {
			shared.Exit(fmt.Sprintf("☹️\tthere was an error healthchecking %s: status %d", operator, res.StatusCode))
		}
	}

	// then let's actually kick off the DKG
	fmt.Println("⏳ starting distributed key generation")
	var responses []api.SignResponse
	for _, operator := range operators {
		response, err := http.Post(fmt.Sprintf("%s/sign", operator), "application/json", bytes.NewBuffer(requestJson))
		if err != nil {
			shared.Exit(fmt.Sprintf("error creating cluster: %v", err))
		}
		if response.StatusCode != http.StatusOK {
			shared.Exit(fmt.Sprintf("error creation cluster. Node return status code %d", response.StatusCode))
		}

		responseBytes, err := io.ReadAll(response.Body)
		if err != nil {
			shared.Exit("error reading response bytes")
		}
		var signResponse api.SignResponse
		err = json.Unmarshal(responseBytes, &signResponse)
		if err != nil {
			shared.Exit(fmt.Sprintf("error unmarshalling json response: %v", err))
		}

		responses = append(responses, signResponse)
	}

	// we write the deposit data to stdout
	fmt.Println("✅ received signed deposit data!")
	fmt.Println(base64.StdEncoding.EncodeToString(responses[0].Signature))

}
