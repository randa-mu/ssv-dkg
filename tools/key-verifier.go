package main

import (
	"encoding/json"
	"fmt"
	"github.com/randa-mu/ssv-dkg/shared"
	"github.com/randa-mu/ssv-dkg/shared/crypto"
	"os"
)

type operatorsFile struct {
	Operators []crypto.Identity `json:"operators"`
}

func main() {
	// the command plus the filepath arg
	if len(os.Args) != 2 {
		shared.Exit("you must provide a filepath of keys to verify")
	}

	file, err := os.ReadFile(os.Args[1])
	if err != nil {
		shared.Exit(fmt.Sprintf("error opening file for verification: %v", err))
	}

	var f operatorsFile
	err = json.Unmarshal(file, &f)
	if err != nil {
		shared.Exit(fmt.Sprintf("error unmarshalling JSON in file: %v", err))
	}
	for _, identity := range f.Operators {
		if err := identity.Verify(); err != nil {
			shared.Exit(fmt.Sprintf("❌ key verification failed for %s", identity.Address))
		}
	}

	fmt.Println("✅ All keys verified successfully!")
}
