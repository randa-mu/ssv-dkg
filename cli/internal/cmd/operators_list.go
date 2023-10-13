package cmd

import (
	"encoding/json"
	"fmt"
	"github.com/randa-mu/ssv-dkg/shared"
	"github.com/randa-mu/ssv-dkg/shared/crypto"
	"github.com/spf13/cobra"
	"io"
	"net/http"
	"os"
	"strings"
)

var ShortFlag bool

type operatorsJsonResponse struct {
	Operators []crypto.Identity `json:"operators"`
}

var operatorsListCmd = &cobra.Command{
	Use:   "list",
	Short: "Lists the DKG-compatible SSV node operators",
	Long:  "Lists the DKG-compatible SSV node operators. By default, sources them from the GitHub repo",
	Run:   listOperators,
}

func init() {
	operatorsListCmd.PersistentFlags().BoolVarP(
		&ShortFlag,
		"short",
		"s",
		false,
		"With short enabled, the stdout input is simpler and machine readable",
	)
}

func listOperators(_ *cobra.Command, _ []string) {
	if sourceFileFlag == "" && sourceUrlFlag == "" {
		shared.Exit("you must provide either a `source-url` or `source-file`!")
	}

	// read the list of operators from file or URL
	var operators []crypto.Identity
	if sourceFileFlag != "" {
		operators = readSourceFile(sourceFileFlag)
	} else {
		operators = readSourceUrl(sourceUrlFlag)
	}

	// verify the signatures of all the operators
	var addresses []string
	for _, op := range operators {
		if err := op.Verify(); err != nil {
			fmt.Println(fmt.Sprintf("🔒 error verifying key for %s", op.Address))
			continue
		}
		addresses = append(addresses, op.Address)
	}

	// print out the pretty or machine-readable results
	if ShortFlag {
		printOperatorsShort(addresses)
	} else {
		printOperatorsPretty(addresses)
	}
}

func readSourceFile(path string) []crypto.Identity {
	contents, err := os.ReadFile(path)
	if err != nil {
		shared.Exit(fmt.Sprintf("there was an error reading the source file: %v", err))
	}

	var j operatorsJsonResponse
	err = json.Unmarshal(contents, &j)
	if err != nil {
		shared.Exit(fmt.Sprintf("there was an error unmarshalling the source file: %v", err))
	}
	return j.Operators
}

func readSourceUrl(url string) []crypto.Identity {
	res, err := http.Get(url)
	if err != nil {
		shared.Exit(fmt.Sprintf("failed to reach URL %s: %v", url, err))
	}
	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		shared.Exit(fmt.Sprintf("failed to read response body"))
	}

	var j operatorsJsonResponse
	err = json.Unmarshal(body, &j)
	if err != nil {
		shared.Exit(fmt.Sprintf("there was an error unmarshalling the HTTP response: %v", err))
	}

	return j.Operators
}

func printOperatorsShort(addresses []string) {
	fmt.Println(strings.Join(addresses, " "))
}

func printOperatorsPretty(addresses []string) {
	if len(addresses) == 0 {
		shared.Exit("Operator list was empty!")
	}

	fmt.Println("⏳\tchecking health of operators")

	var success []string
	var failure []string
	for _, address := range addresses {
		res, err := http.Get(fmt.Sprintf("%s/health", address))
		if err != nil || res.StatusCode != 200 {
			failure = append(failure, address)
		} else {
			success = append(success, address)
		}
	}

	for _, s := range success {
		fmt.Println(fmt.Sprintf("✅\t%s", s))
	}
	for _, f := range failure {
		fmt.Println(fmt.Sprintf("❌\t%s", f))
	}
}
