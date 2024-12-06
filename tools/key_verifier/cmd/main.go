package main

import (
	"fmt"
	"os"

	"github.com/randa-mu/ssv-dkg/shared"
	"github.com/randa-mu/ssv-dkg/tools/key_verifier"
)

func main() {
	if len(os.Args) != 2 {
		shared.Exit("you must provide a filepath of keys to verify")
	}

	err := key_verifier.VerifyKeys(os.Args[1])
	if err != nil {
		shared.Exit(fmt.Sprintf("key validation error: %v", err))
	}
}
