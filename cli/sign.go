package cli

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"net/url"
	"sync"
	"time"

	"github.com/randa-mu/ssv-dkg/shared"
	"github.com/randa-mu/ssv-dkg/shared/api"
	"github.com/randa-mu/ssv-dkg/shared/crypto"
)

func Sign(operators []string, depositData api.UnsignedDepositData, log shared.QuietLogger) (api.SigningOutput, error) {
	numOfNodes := len(operators)
	if numOfNodes != 3 && numOfNodes != 5 && numOfNodes != 7 {
		return api.SigningOutput{}, errors.New("you must pass either 3, 5, or 7 operators to ensure a majority threshold")
	}

	suite := crypto.NewBLSSuite()

	// then fetch their signed public keys
	log.MaybeLog("⏳ contacting nodes")
	identities, err := fetchIdentities(suite, operators)
	if err != nil {
		return api.SigningOutput{}, err
	}

	sessionID, err := createSessionID()
	if err != nil {
		return api.SigningOutput{}, err
	}

	// then let's actually kick off the DKG
	log.MaybeLog("⏳ starting distributed key generation")
	responses, err := runDKG(suite, sessionID, identities, depositData)
	if err != nil {
		return api.SigningOutput{}, err
	}

	groupSig, err := aggregateGroupSignature(suite, responses, depositData)
	if err != nil {
		return api.SigningOutput{}, err
	}

	return api.SigningOutput{
		SessionID:             sessionID,
		GroupSignature:        groupSig.signature,
		PolynomialCommitments: groupSig.publicKey,
		OperatorShares:        extractEncryptedShares(responses),
	}, nil
}

func fetchIdentities(suite crypto.ThresholdScheme, operators []string) ([]crypto.Identity, error) {
	identities := make([]crypto.Identity, len(operators))
	for i, operator := range operators {
		// first we extract the validatorNonce from the input
		address, err := parseOperator(operator)
		if err != nil {
			return nil, err
		}

		// then we fetch the keys for the node
		// perhaps these should be checked against the ones registered in the repo
		client := api.NewSidecarClient(address)
		response, err := client.Identity(api.SidecarIdentityRequest{})
		if err != nil {
			return nil, fmt.Errorf("☹️\tthere was an error health-checking %s: %w", operator, err)
		}
		identity := crypto.Identity{
			Address:   address,
			Public:    response.PublicKey,
			Signature: response.Signature,
		}
		if err = identity.Verify(suite); err != nil {
			return nil, fmt.Errorf("☹️\tthere was an error verifying the identity of operator %s: %w", operator, err)
		}

		identities[i] = identity
	}
	return identities, nil
}

func extractEncryptedShares(arr []api.OperatorResponse) []api.OperatorShare {
	operators := make([]api.OperatorShare, len(arr))
	for i, o := range arr {
		operators[i] = api.OperatorShare{
			Identity:       o.Identity,
			EncryptedShare: o.Response.EncryptedShare,
		}
	}
	return operators
}

func parseOperator(input string) (string, error) {
	if _, err := url.Parse(input); err != nil {
		return "", err
	}
	return input, nil
}

func runDKG(suite crypto.ThresholdScheme, sessionID []byte, identities []crypto.Identity, depositData api.UnsignedDepositData) ([]api.OperatorResponse, error) {
	dkgResponses := shared.SafeList[api.OperatorResponse]{}
	errs := make(chan error, len(identities))
	wg := sync.WaitGroup{}
	wg.Add(len(identities))

	for _, identity := range identities {
		go func(identity crypto.Identity) {
			dkgResponse, err := getVerifiedPartial(suite, identity, depositData, identities, sessionID)
			if err != nil {
				errs <- err
			} else {
				dkgResponses.Append(api.OperatorResponse{
					Identity: identity,
					Response: dkgResponse,
				})
				wg.Done()
			}
		}(identity)
	}

	// we wait for the DKG to finish
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

// a sessionID is used in the DKG to avoid replay attacks
func createSessionID() ([]byte, error) {
	now := time.Now().Unix()
	buf := bytes.NewBuffer(make([]byte, binary.MaxVarintLen64))
	if err := binary.Write(buf, binary.BigEndian, now); err != nil {
		return nil, err
	}
	s := sha256.New()
	if _, err := s.Write(buf.Bytes()); err != nil {
		return nil, err
	}
	return s.Sum(nil), nil
}

func getVerifiedPartial(suite crypto.ThresholdScheme, identity crypto.Identity, depositData api.UnsignedDepositData, identities []crypto.Identity, sessionID []byte) (api.SignResponse, error) {
	client := api.NewSidecarClient(identity.Address)
	data := api.SignRequest{
		Data:      depositData,
		Operators: identities,
		SessionID: sessionID,
	}
	response, err := client.Sign(data)
	if err != nil {
		return api.SignResponse{}, fmt.Errorf("error signing: %w", err)
	}

	message, err := crypto.DepositDataMessage(depositData.ExtractRequired(), response.PublicPolynomial)
	if err != nil {
		return api.SignResponse{}, fmt.Errorf("error building final message: %w", err)
	}
	// verify that the signature over the deposit data verifies for the reported public key
	if err = suite.VerifyPartial(response.PublicPolynomial, message, response.DepositDataPartialSignature); err != nil {
		return api.SignResponse{}, fmt.Errorf("signature did not verify for the signed deposit data for node %s: %w", identity.Address, err)
	}
	return response, nil
}

type groupSignature struct {
	signature []byte
	publicKey []byte
}

func aggregateGroupSignature(suite crypto.ThresholdScheme, responses []api.OperatorResponse, depositData api.UnsignedDepositData) (groupSignature, error) {
	// ensure everybody came up with the same polynomials
	err := verifyPublicPolynomialSame(responses)
	if err != nil {
		return groupSignature{}, err
	}

	// as all the group public keys are the same, we can use the first to verify all the partials
	groupPK := responses[0].Response.PublicPolynomial
	depositDataMessage, err := crypto.DepositDataMessage(depositData.ExtractRequired(), groupPK)
	if err != nil {
		return groupSignature{}, err
	}

	partials := extractPartials(responses)

	signature, err := suite.RecoverSignature(depositDataMessage, groupPK, partials, len(responses))
	if err != nil {
		return groupSignature{}, fmt.Errorf("error aggregating signature: %v", err)
	}

	err = suite.VerifyRecovered(depositDataMessage, groupPK, signature)
	if err != nil {
		return groupSignature{}, fmt.Errorf("error verifying deposit data signature: %v", err)
	}

	return groupSignature{
		signature: signature,
		publicKey: groupPK,
	}, nil
}

func verifyPublicPolynomialSame(arr []api.OperatorResponse) error {
	for i := 1; i < len(arr); i++ {
		// all nodes should return the same group public key or someone is being naughty
		lastPK := arr[i-1].Response.PublicPolynomial
		currentPK := arr[i].Response.PublicPolynomial
		if !bytes.Equal(lastPK, currentPK) {
			return fmt.Errorf("group public key was different for nodes %d and %d", i-1, i)
		}
	}
	return nil
}

func extractPartials(arr []api.OperatorResponse) [][]byte {
	partials := make([][]byte, len(arr))
	for i, o := range arr {
		partials[i] = o.Response.DepositDataPartialSignature
	}
	return partials
}
