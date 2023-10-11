package main

import (
	"fmt"
	"github.com/randa-mu/ssv-dkg/sidecar/internal/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		fmt.Println(err)
	}
}
