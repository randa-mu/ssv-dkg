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

func Sign(operators []string, depositData []byte, log shared.QuietLogger) ([]api.SignResponse, error) {
	// parse and validate the operators provided
	numOfNodes := len(operators)
	if numOfNodes != 3 && numOfNodes != 5 && numOfNodes != 7 {
		return nil, errors.New("you must pass either 3, 5, or 7 operators to ensure a majority threshold")
	}

	suite := crypto.NewBLSSuite()

	log.MaybeLog("⏳ contacting nodes")
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

	sessionID, err := createSessionID()
	if err != nil {
		return nil, err
	}

	// then let's actually kick off the DKG
	log.MaybeLog("⏳ starting distributed key generation")

	responses := shared.SafeList[api.SignResponse]{}
	errs := make(chan error, len(identities))
	wg := sync.WaitGroup{}
	wg.Add(numOfNodes)

	for _, identity := range identities {
		go func(identity crypto.Identity) {
			client := api.NewSidecarClient(identity.Address)
			data := api.SignRequest{
				ValidatorNonce: identity.ValidatorNonce,
				Data:           depositData,
				Operators:      identities,
				SessionID:      sessionID,
			}
			signResponse, err := client.Sign(data)
			if err != nil {
				errs <- fmt.Errorf("error signing: %w", err)
				return
			}

			// verify that the signature over the deposit data verifies for the reported public key
			if err = suite.VerifyPartial(signResponse.ValidatorPK, depositData, signResponse.DepositDataPartialSignature); err != nil {
				errs <- fmt.Errorf("signature did not verify for the signed deposit data for node %s: %w", identity.Address, err)
			}

			responses.Append(signResponse)
			wg.Done()
		}(identity)
	}

	done := make(chan struct{})

	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case err := <-errs:
		return nil, err
	case <-done:
		return responses.Get(), nil
	}
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
