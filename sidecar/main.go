package main

import (
	"fmt"
	"github.com/randa-mu/ssv-dkg/sidecar/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		fmt.Println(err)
	}
}
