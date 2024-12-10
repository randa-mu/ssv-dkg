package key_verifier

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/randa-mu/ssv-dkg/shared/crypto"
)

type operatorsFile struct {
	Operators []crypto.Identity `json:"operators"`
}

func VerifyKeys(filepath string) error {
	suite := crypto.NewBLSSuite()
	file, err := os.ReadFile(filepath)
	if err != nil {
		return fmt.Errorf("error opening file for verification: %w", err)
	}

	var f operatorsFile
	err = json.Unmarshal(file, &f)
	if err != nil {
		return fmt.Errorf("error unmarshalling JSON in file: %w", err)
	}
	for _, identity := range f.Operators {
		if err := identity.Verify(suite); err != nil {
			return fmt.Errorf("❌ key verification failed for %s", identity.Address)
		}
	}

	fmt.Println("✅ All keys verified successfully!")
	return nil
}
