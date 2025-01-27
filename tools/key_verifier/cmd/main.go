package main

import (
	"log"
	"os"

	"github.com/randa-mu/ssv-dkg/tools/key_verifier"
)

func main() {
	if len(os.Args) != 2 {
		log.Fatal("you must provide a filepath of keys to verify")
	}

	err := key_verifier.VerifyKeys(os.Args[1])
	if err != nil {
		log.Fatalf("key validation error: %v", err)
	}
}
