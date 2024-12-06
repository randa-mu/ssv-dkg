package cli

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path"

	"github.com/randa-mu/ssv-dkg/shared/api"
)

func CreateFilename(stateDirectory string, output api.SigningOutput) string {
	return path.Join(stateDirectory, fmt.Sprintf("%s.json", hex.EncodeToString(output.SessionID)))
}

// StoreState stores the JSON encoded `api.SigningOutput` in a flat file.
// it will overwrite any file that is presently there
// it returns the json bytes on file write failure, so they can be printed to console
// so users don't just lose their DKG state completely if e.g. they write somewhere without perms
func StoreState(filepath string, output api.SigningOutput) ([]byte, error) {
	return storeWithFlags(filepath, output, os.O_WRONLY)
}

// StoreStateIfNotExists stores the JSON encoded `api.SigningOutput` in a flat file.
// it will fail if a file with the given name already exists
// it returns the json bytes on file write failure, so they can be printed to console
// so users don't just lose their DKG state completely if e.g. they write somewhere without perms
func StoreStateIfNotExists(filepath string, output api.SigningOutput) ([]byte, error) {
	return storeWithFlags(filepath, output, os.O_WRONLY|os.O_CREATE|os.O_EXCL)
}

func storeWithFlags(filepath string, output api.SigningOutput, flag int) ([]byte, error) {
	bytes, err := json.Marshal(output)
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

// LoadState loads and unmarshalls the JSON encoded `api.SigningOutput` from a flat file.
func LoadState(filepath string) (api.SigningOutput, error) {
	bytes, err := os.ReadFile(filepath)
	if err != nil {
		return api.SigningOutput{}, err
	}

	var s api.SigningOutput
	err = json.Unmarshal(bytes, &s)
	return s, err
}
