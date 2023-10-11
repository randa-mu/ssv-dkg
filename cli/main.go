package main

import (
	"fmt"
	"github.com/randa-mu/ssv-dkg/cli/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		fmt.Println(err)
	}
}
