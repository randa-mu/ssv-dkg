package sidecar

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/randa-mu/ssv-dkg/shared/crypto"
	"github.com/randa-mu/ssv-dkg/sidecar/internal/util"
)

func GenerateKey(keyPath string) error {
	suite := crypto.NewBLSSuite()
	kp, err := suite.CreateKeypair()
	if err != nil {
		return fmt.Errorf("failed to create keypair: %w", err)
	}

	err = util.StoreKeypair(kp, keyPath)
	if err != nil {
		return fmt.Errorf("failed to store keypair: %w", err)
	}
	return nil
}

func SignKey(url string, keyPath string) ([]byte, error) {
	if url == "" {
		return nil, errors.New("tou must pass a URL to associate the keypair with")
	}

	keypair, err := util.LoadKeypair(keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load keypair from %s: %w", keyPath, err)
	}

	suite := crypto.NewBLSSuite()
	identity, err := keypair.SelfSign(suite, url)
	if err != nil {
		return nil, fmt.Errorf("failed to sign address: %w", err)
	}

	bytes, err := json.Marshal(identity)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal json for identity: %w", err)
	}
	return bytes, nil
}
