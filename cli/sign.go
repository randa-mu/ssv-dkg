package cli

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/randa-mu/ssv-dkg/shared"
	"github.com/randa-mu/ssv-dkg/shared/api"
	"github.com/randa-mu/ssv-dkg/shared/crypto"
	"sync"
	"time"
)

func Sign(operators []string, depositData []byte, log shared.QuietLogger) ([]api.SignResponse, error) {
	// parse and validate the operators provided
	numOfNodes := len(operators)
	if numOfNodes != 3 && numOfNodes != 5 && numOfNodes != 7 {
		return nil, errors.New("you must pass either 3, 5, or 7 operators to ensure a majority threshold")
	}

	suite := crypto.NewBLSSuite()

	// let's first health-check everything
	log.MaybeLog("⏳ contacting nodes")
	identities := make([]crypto.Identity, len(operators))
	for i, operator := range operators {
		client := api.NewSidecarClient(operator)
		response, err := client.Identity()
		if err != nil {
			return nil, fmt.Errorf("☹️\tthere was an error health-checking %s: %v", operator, err)
		}
		identity := crypto.Identity{
			Address:   response.Address,
			Public:    response.PublicKey,
			Signature: response.Signature,
		}
		err = identity.Verify(suite)
		if err != nil {
			return nil, fmt.Errorf("☹️\tthere was an error verifying the identity of operator %s: %v", operator, err)
		}

		identities[i] = identity
	}

	sessionID, err := createSessionID()
	if err != nil {
		return nil, err
	}
	data := api.SignRequest{
		Data:      depositData,
		Operators: identities,
		SessionID: sessionID,
	}

	// then let's actually kick off the DKG
	log.MaybeLog("⏳ starting distributed key generation")

	responses := shared.SafeList[api.SignResponse]{}
	errs := make(chan error, 1)
	wg := sync.WaitGroup{}
	wg.Add(numOfNodes)
	for _, operator := range operators {
		go func(operator string) {

			client := api.NewSidecarClient(operator)
			signResponse, err := client.Sign(data)
			if err != nil {
				errs <- fmt.Errorf("error signing: %v", err)
				return
			}

			publicPolynomial, err := crypto.UnmarshalPubPoly(suite, signResponse.ValidatorPK)
			if err != nil {
				errs <- err
				return
			}
			// verify that the signature over the deposit data verifies for the reported public key
			err = suite.VerifyPartial(&publicPolynomial, depositData, signResponse.DepositDataPartialSignature)
			if err != nil {
				errs <- fmt.Errorf("signature did not verify for the signed deposit data for node %s: %v", operator, err)
			}

			responses.Append(signResponse)
			wg.Done()
		}(operator)
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
