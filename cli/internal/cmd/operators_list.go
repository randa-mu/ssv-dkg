package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/randa-mu/ssv-dkg/shared"
	"github.com/randa-mu/ssv-dkg/shared/crypto"
)

var quietFlag bool

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
		&quietFlag,
		"quiet",
		"q",
		false,
		"With short enabled, the stdout input is simpler and machine readable",
	)
}

func listOperators(_ *cobra.Command, _ []string) {
	if sourceFileFlag == "" && sourceUrlFlag == "" {
		shared.Exit("you must provide either a `source-url` or `source-file`!")
	}

	log := shared.QuietLogger{Quiet: quietFlag}

	// read the list of operators from file or URL
	var operators []crypto.Identity
	if sourceFileFlag != "" {
		log.MaybeLog("📂 reading operators from a local file")
		operators = readSourceFile(sourceFileFlag)
	} else {
		log.MaybeLog("🌐 reading operators from the internet")
		operators = readSourceUrl(sourceUrlFlag)
	}

	// verify the signatures of all the operators
	operatorIdentities := make([]crypto.Identity, 0, len(operators))
	suite := crypto.NewBLSSuite()

	for _, op := range operators {
		if err := op.Verify(suite); err != nil {
			log.MaybeLog(fmt.Sprintf("🔒 error verifying key for %s", op.Address))
			continue
		}
		operatorIdentities = append(operatorIdentities, op)
	}

	// print out the pretty or machine-readable results
	if quietFlag {
		printOperatorsQuiet(log, operatorIdentities)
	} else {
		printOperatorsPretty(log, operatorIdentities)
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
		shared.Exit("failed to read response body")
	}

	var j operatorsJsonResponse
	err = json.Unmarshal(body, &j)
	if err != nil {
		shared.Exit(fmt.Sprintf("there was an error unmarshalling the HTTP response: %v", err))
	}

	return j.Operators
}

func printOperatorsPretty(log shared.QuietLogger, operators []crypto.Identity) {
	if len(operators) == 0 {
		shared.Exit("Operator list was empty!")
	}

	log.Log("⏳checking health of operators")

	success := make([]crypto.Identity, 0, len(operators))
	failure := make([]crypto.Identity, 0, len(operators))
	for _, o := range operators {
		res, err := http.Get(fmt.Sprintf("%s/health", o.Address))
		if err != nil || res.StatusCode != 200 {
			failure = append(failure, o)
		} else {
			success = append(success, o)
		}
	}

	log.Log(fmt.Sprintf("Status\tID\tAddress"))
	for _, s := range success {
		log.Log(fmt.Sprintf("✅\t%d\t%s", s.OperatorID, s.Address))
	}
	for _, f := range failure {
		log.Log(fmt.Sprintf("❌\t%d\t%s", f.OperatorID, f.Address))
	}
}

func printOperatorsQuiet(log shared.QuietLogger, operators []crypto.Identity) {
	entries := make([]string, len(operators))
	for i, operator := range operators {
		entries[i] = fmt.Sprintf("%d", operator.OperatorID)
	}
	log.Log(strings.Join(entries, " "))
}
