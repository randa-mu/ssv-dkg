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
	"golang.org/x/exp/slices"
)

// Sign performs a distributed key generation between the operators provided
// then aggregates a group signature over the deposit data merkle root
// then aggregates a group signature over the validator nonce
func Sign(config api.SignatureConfig, log shared.QuietLogger) (api.SigningOutput, error) {
	// SSV supports 3f+1 nodes up to f=4
	numOfNodes := len(config.Operators)
	if numOfNodes != 4 && numOfNodes != 7 && numOfNodes != 10 && numOfNodes != 13 {
		return api.SigningOutput{}, errors.New("you must pass either 4, 7, 10 or 13 operators to ensure a majority threshold")
	}

	suite := crypto.NewBLSSuite()

	// then fetch their signed public keys
	log.MaybeLog("⏳ contacting nodes")
	identities, err := fetchIdentities(suite, config.Operators)
	if err != nil {
		return api.SigningOutput{}, err
	}

	sessionID, err := createSessionID()
	if err != nil {
		return api.SigningOutput{}, err
	}

	// then let's actually kick off the DKG
	log.MaybeLog("⏳ starting distributed key generation")
	responses, err := runDKG(suite, sessionID, identities, config.DepositData, config.Owner)
	if err != nil {
		return api.SigningOutput{}, err
	}

	// we sort the responses by operatorID, though they ought to already be sorted
	slices.SortStableFunc(responses, func(a, b api.OperatorResponse) int {
		return int(a.Identity.OperatorID) - int(b.Identity.OperatorID)
	})

	// if all the group public keys are the same,
	if err := verifyPublicPolynomialSame(responses); err != nil {
		return api.SigningOutput{}, fmt.Errorf("not every operator came up with the same public key: %v", err)
	}
	// we can use the first to verify all the partials
	publicPolynomial := responses[0].Response.PublicPolynomial
	groupPublicKey := crypto.ExtractGroupPublicKey(suite, shared.Clone(publicPolynomial))

	// then we aggregate and verify the deposit data signature
	depositDataMessage, err := crypto.DepositMessageSigningRoot(config.DepositData.IntoMessage(shared.Clone(groupPublicKey)), config.DepositData.ForkVersion)
	if err != nil {
		return api.SigningOutput{}, fmt.Errorf("failed to create deposit data message: %v", err)
	}

	depositDataPartials, err := extractDepositDataPartials(responses)
	if err != nil {
		return api.SigningOutput{}, fmt.Errorf("error extracting deposit data partials: %v", err)
	}

	depositDataSignature, err := aggregateGroupSignature(suite, depositDataPartials, publicPolynomial, depositDataMessage)
	if err != nil {
		return api.SigningOutput{}, fmt.Errorf("error aggregating deposit data signature: %v", err)
	}
	if err = suite.Verify(depositDataMessage, groupPublicKey, depositDataSignature); err != nil {
		return api.SigningOutput{}, fmt.Errorf("failed to verify deposit data signature: %v", err)
	}

	// then we aggregate and verify the validator nonce signature
	validatorNonceMessage, err := crypto.ValidatorNonceMessage(config.Owner.Address, config.Owner.ValidatorNonce)
	if err != nil {
		return api.SigningOutput{}, fmt.Errorf("your ethereum address wasn't correct: %v", err)
	}

	validatorNoncePartials, err := extractValidatorNoncePartials(responses)
	if err != nil {
		return api.SigningOutput{}, fmt.Errorf("error extracting partials for validator nonce signature: %v", err)
	}
	validatorNonceSignature, err := aggregateGroupSignature(suite, validatorNoncePartials, publicPolynomial, validatorNonceMessage)
	if err != nil {
		return api.SigningOutput{}, fmt.Errorf("error aggregating validator nonce signature: %v", err)
	}

	if err = suite.Verify(validatorNonceMessage, groupPublicKey, validatorNonceSignature); err != nil {
		return api.SigningOutput{}, fmt.Errorf("failed to verify validator nonce signature: %v", err)
	}

	// and finally we extract some relevant bits before returning all the info
	output := api.SigningOutput{
		SessionID:               sessionID,
		GroupPublicPolynomial:   publicPolynomial,
		OperatorShares:          extractEncryptedShares(responses),
		DepositDataSignature:    depositDataSignature,
		ValidatorNonceSignature: validatorNonceSignature,
	}

	return output, nil
}

func fetchIdentities(suite crypto.ThresholdScheme, operators []string) ([]crypto.Identity, error) {
	identities := make([]crypto.Identity, len(operators))
	for i, operator := range operators {
		// first we parse the operator address to ensure it's correct
		address, err := parseOperator(operator)
		if err != nil {
			return nil, err
		}

		// then we fetch the keys for the node
		// perhaps these should be checked against the ones registered in the repo
		client := api.NewSidecarClient(address)
		response, err := client.Identity()
		if err != nil {
			return nil, fmt.Errorf("☹️\tthere was an error health-checking %s: %w", operator, err)
		}
		identity := crypto.Identity{
			Address:    address,
			OperatorID: response.OperatorID,
			Public:     response.PublicKey,
			Signature:  response.Signature,
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
			SharePublicKey: o.Response.SharePublicKey,
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

func runDKG(suite crypto.ThresholdScheme, sessionID []byte, identities []crypto.Identity, depositData api.UnsignedDepositData, owner api.OwnerConfig) ([]api.OperatorResponse, error) {
	dkgResponses := shared.SafeList[api.OperatorResponse]{}
	errs := make(chan error, len(identities))
	wg := sync.WaitGroup{}
	wg.Add(len(identities))

	for _, identity := range identities {
		go func(identity crypto.Identity) {
			dkgResponse, err := singleNodeRunDKG(suite, identity, sessionID, identities, depositData, owner)
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

// singleNodeRunDKG kicks off the DKG for a single node, waits for its response and verifies the necessary fields
func singleNodeRunDKG(suite crypto.ThresholdScheme, identity crypto.Identity, sessionID []byte, identities []crypto.Identity, depositData api.UnsignedDepositData, owner api.OwnerConfig) (api.SignResponse, error) {
	client := api.NewSidecarClient(identity.Address)

	data := api.SignRequest{
		DepositData: depositData,
		Operators:   identities,
		SessionID:   sessionID,
		OwnerConfig: owner,
	}
	response, err := client.Sign(data)
	if err != nil {
		return api.SignResponse{}, fmt.Errorf("error signing: %w", err)
	}

	err = signatureResponseVerifies(suite, identity, depositData, owner, response)
	if err != nil {
		return api.SignResponse{}, fmt.Errorf("error verifying signing response: %w", err)
	}

	return response, nil
}

func signatureResponseVerifies(suite crypto.ThresholdScheme, identity crypto.Identity, depositData api.UnsignedDepositData, owner api.OwnerConfig, response api.SignResponse) error {
	// verify that the signature over the validator nonce verifies to prevent attempts to register the same validator twice
	validatorNonceMessage, err := crypto.ValidatorNonceMessage(owner.Address, owner.ValidatorNonce)
	if err != nil {
		return fmt.Errorf("your ETH address was not correct")
	}
	// we need to keccak first the validator nonce message
	//
	if err := suite.VerifyPartial(response.PublicPolynomial, validatorNonceMessage, response.ValidatorNoncePartialSignature); err != nil {
		return fmt.Errorf("signature did not verify for the signed validator nonce for node %s: %w", identity.Address, err)
	}

	// verify that the signature over the deposit data verifies for the reported public key
	groupPublicKey := crypto.ExtractGroupPublicKey(suite, response.PublicPolynomial)
	message, err := crypto.DepositMessageSigningRoot(depositData.IntoMessage(shared.Clone(groupPublicKey)), depositData.ForkVersion)
	if err != nil {
		return fmt.Errorf("error building final message: %w", err)
	}
	if err = suite.VerifyPartial(response.PublicPolynomial, message, response.DepositDataPartialSignature); err != nil {
		return fmt.Errorf("signature did not verify for the signed deposit data for node %s: %w", identity.Address, err)
	}
	return nil
}

// aggregateGroupSignature aggregates partials from all the operators and verifies the output
func aggregateGroupSignature(suite crypto.ThresholdScheme, partials [][]byte, groupPublicPolynomial []byte, message []byte) ([]byte, error) {
	signature, err := suite.RecoverSignature(message, groupPublicPolynomial, partials, len(partials))
	if err != nil {
		return nil, fmt.Errorf("error aggregating signature: %v", err)
	}

	err = suite.VerifyRecovered(message, groupPublicPolynomial, signature)
	if err != nil {
		return nil, fmt.Errorf("error verifying deposit data signature: %v", err)
	}

	return signature, nil
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

func extractDepositDataPartials(arr []api.OperatorResponse) ([][]byte, error) {
	partials := make([][]byte, len(arr))

	for i, o := range arr {
		partials[i] = o.Response.DepositDataPartialSignature

	}
	return partials, nil
}

func extractValidatorNoncePartials(arr []api.OperatorResponse) ([][]byte, error) {
	partials := make([][]byte, len(arr))

	for i, o := range arr {
		partials[i] = o.Response.ValidatorNoncePartialSignature

	}
	return partials, nil
}
