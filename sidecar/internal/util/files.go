package util

import (
	"encoding/json"
	"fmt"
	"github.com/randa-mu/ssv-dkg/sidecar/internal/crypto"
	"os"
	"path/filepath"
)

func StoreKeypair(kp crypto.Keypair, path string) error {
	err := os.MkdirAll(filepath.Dir(path), os.ModePerm)
	if err != nil {
		return fmt.Errorf("failed to create dir at for path %s: %v", path, err)
	}

	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to create a file at path %s for the keypair: %v", path, err)
	}
	defer file.Close()

	err = file.Chmod(0600)
	if err != nil {
		return fmt.Errorf("failed to set the correct file permissions for the keypair: %v", err)
	}

	bytes, err := json.Marshal(kp)
	if err != nil {
		return fmt.Errorf("failed to marshal the keypair as JSON: %v", err)
	}

	_, err = file.Write(bytes)
	if err != nil {
		return fmt.Errorf("failed to write keypair to file: %v", err)
	}

	return nil
}

func LoadKeypair(path string) (crypto.Keypair, error) {
	file, err := os.ReadFile(path)
	if err != nil {
		return crypto.Keypair{}, fmt.Errorf("failed to read keypair at %s: %v", path, err)
	}

	var keypair crypto.Keypair
	err = json.Unmarshal(file, &keypair)
	if err != nil {
		return crypto.Keypair{}, fmt.Errorf("could not unmarshal key: %v", err)
	}

	return keypair, nil
}
