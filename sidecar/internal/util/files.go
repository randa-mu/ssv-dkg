package util

import (
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"

	"github.com/randa-mu/ssv-dkg/shared/crypto"
)

const KeySuffix = "keypair.json"

func StoreKeypair(kp crypto.Keypair, path string) error {
	err := os.MkdirAll(filepath.Dir(path), os.ModePerm)
	if err != nil {
		return fmt.Errorf("failed to create dir at for path %s: %w", path, err)
	}

	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to create a file at path %s for the keypair: %w", path, err)
	}
	defer file.Close()

	err = file.Chmod(0600)
	if err != nil {
		return fmt.Errorf("failed to set the correct file permissions for the keypair: %w", err)
	}

	bytes, err := json.Marshal(kp)
	if err != nil {
		return fmt.Errorf("failed to marshal the keypair as JSON: %w", err)
	}

	_, err = file.Write(bytes)
	if err != nil {
		return fmt.Errorf("failed to write keypair to file: %w", err)
	}

	return nil
}

func LoadKeypair(stateDir string) (crypto.Keypair, error) {
	file, err := os.ReadFile(path.Join(stateDir, KeySuffix))
	if err != nil {
		return crypto.Keypair{}, fmt.Errorf("failed to read keypair at %s: %w", stateDir, err)
	}

	var keypair crypto.Keypair
	err = json.Unmarshal(file, &keypair)
	if err != nil {
		return crypto.Keypair{}, fmt.Errorf("could not unmarshal key: %w", err)
	}

	return keypair, nil
}
