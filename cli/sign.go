package cli

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/randa-mu/ssv-dkg/shared"
	"github.com/randa-mu/ssv-dkg/shared/api"
	"github.com/randa-mu/ssv-dkg/shared/crypto"
)

type SigningOutput struct {
	SessionID             []byte          `json:"session_id"`
	GroupSignature        []byte          `json:"group_signature"`
	PolynomialCommitments []byte          `json:"group_public_key"`
	OperatorShares        []OperatorShare `json:"operator_shares"`
}

type OperatorShare struct {
	Identity       crypto.Identity `json:"identity"`
	EncryptedShare []byte          `json:"encrypted_share"`
}

type operatorResponse struct {
	identity crypto.Identity
	response api.SignResponse
}

func Sign(operators []string, depositData []byte, log shared.QuietLogger) (SigningOutput, error) {
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

	sessionID, err := createSessionID()
	if err != nil {
		return SigningOutput{}, err
	}

	// then let's actually kick off the DKG
	log.MaybeLog("⏳ starting distributed key generation")
	responses, err := runDKG(suite, sessionID, identities, depositData)
	if err != nil {
		return SigningOutput{}, err
	}

	groupSig, err := aggregateGroupSignature(suite, responses, depositData)
	if err != nil {
		return SigningOutput{}, err
	}

	return SigningOutput{
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
		nonce, address, err := parseOperator(operator)
		if err != nil {
			return nil, err
		}

		// then we fetch the keys for the node
		// perhaps these should be checked against the ones registered in the repo
		client := api.NewSidecarClient(address)
		response, err := client.Identity(api.SidecarIdentityRequest{ValidatorNonce: nonce})
		if err != nil {
			return nil, fmt.Errorf("☹️\tthere was an error health-checking %s: %w", operator, err)
		}
		identity := crypto.Identity{
			ValidatorNonce: nonce,
			Address:        address,
			Public:         response.PublicKey,
			Signature:      response.Signature,
		}
		if err = identity.Verify(suite); err != nil {
			return nil, fmt.Errorf("☹️\tthere was an error verifying the identity of operator %s: %w", operator, err)
		}

		identities[i] = identity
	}
	return identities, nil
}

func extractEncryptedShares(arr []operatorResponse) []OperatorShare {
	operators := make([]OperatorShare, len(arr))
	for i, o := range arr {
		operators[i] = OperatorShare{
			Identity:       o.identity,
			EncryptedShare: o.response.EncryptedShare,
		}
	}
	return operators
}

// parseOperator takes a string in form `$validatorNonce,$address` and separates it out
// e.g. "4,https://example.com" returns `4, https://example.com, nil`
func parseOperator(input string) (uint32, string, error) {
	parts := strings.Split(input, ",")
	l := len(parts)

	if l < 2 {
		return 0, "", errors.New("operator tuple didn't have enough commas in it")
	}
	if l > 2 {
		return 0, "", errors.New("operator tuple had too many commas in it")
	}

	validatorNonce, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0, "", errors.New("validatorNonce for the operator must be a number")
	}

	return uint32(validatorNonce), parts[1], nil
}

func runDKG(suite crypto.ThresholdScheme, sessionID []byte, identities []crypto.Identity, depositData []byte) ([]operatorResponse, error) {
	dkgResponses := shared.SafeList[operatorResponse]{}
	errs := make(chan error, len(identities))
	wg := sync.WaitGroup{}
	wg.Add(len(identities))

	for _, identity := range identities {
		go func(identity crypto.Identity) {
			dkgResponse, err := getVerifiedPartial(suite, identity, depositData, identities, sessionID)
			if err != nil {
				errs <- err
			} else {
				dkgResponses.Append(operatorResponse{
					identity: identity,
					response: dkgResponse,
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

func getVerifiedPartial(suite crypto.ThresholdScheme, identity crypto.Identity, depositData []byte, identities []crypto.Identity, sessionID []byte) (api.SignResponse, error) {
	client := api.NewSidecarClient(identity.Address)
	data := api.SignRequest{
		ValidatorNonce: identity.ValidatorNonce,
		Data:           depositData,
		Operators:      identities,
		SessionID:      sessionID,
	}
	response, err := client.Sign(data)
	if err != nil {
		return api.SignResponse{}, fmt.Errorf("error signing: %w", err)
	}

	// verify that the signature over the deposit data verifies for the reported public key
	if err = suite.VerifyPartial(response.PublicPolynomial, depositData, response.DepositDataPartialSignature); err != nil {
		return api.SignResponse{}, fmt.Errorf("signature did not verify for the signed deposit data for node %s: %w", identity.Address, err)
	}
	return response, nil
}

type groupSignature struct {
	signature []byte
	publicKey []byte
}

func aggregateGroupSignature(suite crypto.ThresholdScheme, responses []operatorResponse, depositData []byte) (groupSignature, error) {
	// ensure everybody came up with the same polynomials
	err := verifyPublicPolynomialSame(responses)
	if err != nil {
		return groupSignature{}, err
	}

	// as all the group public keys are the same, we can use the first to verify all the partials
	groupPK := responses[0].response.PublicPolynomial

	partials := extractPartials(responses)

	signature, err := suite.RecoverSignature(depositData, groupPK, partials, len(responses))
	if err != nil {
		return groupSignature{}, fmt.Errorf("error aggregating signature: %v", err)
	}

	err = suite.VerifyRecovered(depositData, groupPK, signature)
	if err != nil {
		return groupSignature{}, fmt.Errorf("error verifying deposit data signature: %v", err)
	}

	return groupSignature{
		signature: signature,
		publicKey: groupPK,
	}, nil
}

func verifyPublicPolynomialSame(arr []operatorResponse) error {
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

func extractPartials(arr []operatorResponse) [][]byte {
	partials := make([][]byte, len(arr))
	for i, o := range arr {
		partials[i] = o.response.DepositDataPartialSignature
	}
	return partials
}
