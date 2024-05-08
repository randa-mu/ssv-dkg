package cli

import (
	"bytes"
	"errors"
	"fmt"
	"sync"

	"github.com/randa-mu/ssv-dkg/shared"
	"github.com/randa-mu/ssv-dkg/shared/api"
	"github.com/randa-mu/ssv-dkg/shared/crypto"
)

func Reshare(operators []string, state SigningOutput, log shared.QuietLogger) (SigningOutput, error) {
	numOfNodes := len(operators)
	if numOfNodes != 3 && numOfNodes != 5 && numOfNodes != 7 {
		return SigningOutput{}, errors.New("you must pass either 3, 5, or 7 operators to ensure a majority threshold")
	}

	suite := crypto.NewBLSSuite()

	// then fetch their signed public keys
	log.MaybeLog("⏳ contacting nodes")
	identities, err := fetchIdentities(suite, operators)
	if err != nil {
		return SigningOutput{}, err
	}

	// then we run the reshare with them
	operatorResponses, err := runReshare(state, identities)
	if err != nil {
		return SigningOutput{}, err
	}

	// if any nodes fail to qualify, we fail the reshare
	// really the sidecars should know this themselves and return an error, but worth sanity checking anyway
	if len(operatorResponses) != numOfNodes {
		return SigningOutput{}, fmt.Errorf("some nodes did not complete the resharing. Count: %d, expected %d", len(operatorResponses), numOfNodes)
	}

	// we do some sanity checks on the returned details to ensure the public key hasn't changed
	err = verifyPublicPolynomialSameReshare(operatorResponses)
	if err != nil {
		return SigningOutput{}, err
	}
	groupPK, err := extractGroupPublicKey(suite, operatorResponses[0].response.PublicPolynomial)
	if err != nil {
		return SigningOutput{}, err
	}
	oldGroupPK, err := extractGroupPublicKey(suite, state.PolynomialCommitments)
	if err != nil {
		return SigningOutput{}, err
	}

	if !bytes.Equal(groupPK, oldGroupPK) {
		return SigningOutput{}, errors.New("the new public key didn't match the old one")
	}

	operatorShares := make([]OperatorShare, len(operatorResponses))
	for i, r := range operatorResponses {
		operatorShares[i] = OperatorShare{
			Identity:       r.identity,
			EncryptedShare: r.response.EncryptedShare,
		}
	}

	return SigningOutput{
		SessionID:             state.SessionID,
		GroupSignature:        state.GroupSignature,
		PolynomialCommitments: state.PolynomialCommitments,
		OperatorShares:        operatorShares,
	}, nil
}

type operatorReshareResponse struct {
	identity crypto.Identity
	response api.ReshareResponse
}

func runReshare(state SigningOutput, identities []crypto.Identity) ([]operatorReshareResponse, error) {
	dkgResponses := shared.SafeList[operatorReshareResponse]{}
	errs := make(chan error, len(identities))
	wg := sync.WaitGroup{}
	wg.Add(len(identities))

	for _, identity := range identities {
		go func(identity crypto.Identity) {
			client := api.NewSidecarClient(identity.Address)
			reshareResponse, err := client.Reshare(api.ReshareRequest{
				SessionID:      state.SessionID,
				ValidatorNonce: identity.ValidatorNonce,
				Operators:      identities,
			})
			if err != nil {
				errs <- err
			} else {
				dkgResponses.Append(operatorReshareResponse{
					identity: identity,
					response: reshareResponse,
				})
				wg.Done()
			}
		}(identity)
	}

	// we wait for the reshare to finish
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case err := <-errs:
		return nil, err
	case <-done:
		break
	}

	return dkgResponses.Get(), nil
}

func verifyPublicPolynomialSameReshare(arr []operatorReshareResponse) error {
	for i := 1; i < len(arr); i++ {
		// all nodes should return the same group public key or someone is being naughty
		lastPK := arr[i-1].response.PublicPolynomial
		currentPK := arr[i].response.PublicPolynomial
		if !bytes.Equal(lastPK, currentPK) {
			return fmt.Errorf("group public key was different for nodes %d and %d", i-1, i)
		}
	}
	return nil
}

func extractGroupPublicKey(suite crypto.ThresholdScheme, publicPolyBytes []byte) ([]byte, error) {
	pubPoly, err := crypto.UnmarshalPubPoly(suite, publicPolyBytes)
	if err != nil {
		return nil, err
	}
	_, commits := pubPoly.Info()

	firstCommit := commits[0]

	return firstCommit.MarshalBinary()
}
