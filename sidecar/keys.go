package sidecar

import (
	"encoding/json"
	"errors"
	"fmt"
	"path"

	"github.com/randa-mu/ssv-dkg/shared/crypto"
	"github.com/randa-mu/ssv-dkg/sidecar/internal/util"
)

func GenerateKey(stateDir string) error {
	suite := crypto.NewBLSSuite()
	kp, err := suite.CreateKeypair()
	if err != nil {
		return fmt.Errorf("failed to create keypair: %w", err)
	}

	keyPath := path.Join(stateDir, util.KeySuffix)
	err = util.StoreKeypair(kp, keyPath)
	if err != nil {
		return fmt.Errorf("failed to store keypair: %w", err)
	}
	return nil
}

func SignKey(url string, validatorNonce uint32, stateDir string) ([]byte, error) {
	if url == "" {
		return nil, errors.New("you must pass a URL to associate the keypair with")
	}
	if validatorNonce == 0 {
		return nil, errors.New("you must provide a valid validator nonce")
	}

	keypair, err := util.LoadKeypair(stateDir)
	if err != nil {
		keyPath := path.Join(stateDir, util.KeySuffix)
		return nil, fmt.Errorf("failed to load keypair from %s: %w", keyPath, err)
	}

	suite := crypto.NewBLSSuite()
	identity, err := keypair.SelfSign(suite, url, validatorNonce)
	if err != nil {
		return nil, fmt.Errorf("failed to sign address: %w", err)
	}

	bytes, err := json.Marshal(identity)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal json for identity: %w", err)
	}
	return bytes, nil
}
