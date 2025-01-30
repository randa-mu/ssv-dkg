package files

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path"

	"github.com/randa-mu/ssv-dkg/shared/api"
)

type StoredState struct {
	OwnerConfig   api.OwnerConfig
	SigningOutput api.SigningOutput
}

const StateFileName = "state.json"
const DepositDataFileName = "signed_deposit_data.json"
const KeyShareFileName = "keystore.json"

func CreateFilename(stateDirectory string, output api.SigningOutput, filename string) string {
	return path.Join(stateDirectory, fmt.Sprintf("%s/%s", hex.EncodeToString(output.SessionID), filename))
}

// StoreState stores the JSON encoded `StoredState` in a flat file.
// it will overwrite any file that is presently there
// it returns the json bytes on file write failure, so they can be printed to console
// so users don't just lose their DKG state completely if e.g. they write somewhere without perms
func StoreState(filepath string, state StoredState) ([]byte, error) {
	return storeWithFlags(filepath, state, os.O_WRONLY)
}

// StoreStateIfNotExists stores the JSON encoded state in a flat file.
// it will fail if a file with the given name already exists
// it returns the json bytes on file write failure, so they can be printed to console
// so users don't just lose their DKG state completely if e.g. they write somewhere without perms
func StoreStateIfNotExists(filepath string, state any) ([]byte, error) {
	return storeWithFlags(filepath, state, os.O_WRONLY|os.O_CREATE|os.O_EXCL)
}

func storeWithFlags(filepath string, state any, flag int) ([]byte, error) {
	bytes, err := json.Marshal(state)
	if err != nil {
		return nil, err
	}

	file, err := os.OpenFile(filepath, flag, 0o755)
	if err != nil {
		return bytes, err
	}

	_, err = file.Write(bytes)
	return bytes, err
}

// LoadState loads and unmarshals the JSON encoded `StoredState` from a flat file.
func LoadState(filepath string) (StoredState, error) {
	bytes, err := os.ReadFile(filepath)
	if err != nil {
		return StoredState{}, err
	}

	var s StoredState
	err = json.Unmarshal(bytes, &s)
	return s, err
}
