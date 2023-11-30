package cli

import (
	"errors"
	"fmt"
	"github.com/randa-mu/ssv-dkg/shared"
	"github.com/randa-mu/ssv-dkg/shared/api"
	"github.com/randa-mu/ssv-dkg/shared/crypto"
	"net/http"
)

func Sign(operators []string, depositData []byte, log shared.QuietLogger) ([]api.SignResponse, error) {
	// parse and validate the operators provided
	numOfNodes := len(operators)
	if numOfNodes != 3 && numOfNodes != 5 && numOfNodes != 7 {
		return nil, errors.New("you must pass either 3, 5, or 7 operators to ensure a majority threshold")
	}

	// let's first health-check everything
	log.MaybeLog("⏳ contacting nodes")
	for _, operator := range operators {
		res, err := http.Get(fmt.Sprintf("%s/health", operator))
		if err != nil {
			return nil, fmt.Errorf("☹️\tthere was an error health-checking %s: %v", operator, err)
		}
		if res.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("☹️\tthere was an error health-checking %s: status %d", operator, res.StatusCode)
		}
	}

	data := api.SignRequest{
		Data: depositData,
	}

	// then let's actually kick off the DKG
	log.MaybeLog("⏳ starting distributed key generation")
	suite := crypto.NewBLSSuite()
	var responses []api.SignResponse
	for _, operator := range operators {
		client := api.NewSidecarClient(operator)

		signResponse, err := client.Sign(data)
		if err != nil {
			return nil, fmt.Errorf("error signing: %v", err)
		}

		// verify that the signature over the deposit data verifies for the reported public key
		err = suite.Verify(depositData, signResponse.SharePK, signResponse.DepositDataPartialSignature)
		if err != nil {
			return nil, fmt.Errorf("signature did not verify for the signed deposit data for node %s: %v", operator, err)
		}

		responses = append(responses, signResponse)
	}

	return responses, nil
}
