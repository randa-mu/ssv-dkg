package main

import (
	"os"
	"strconv"

)

func main() {
	if len(os.Args) != 2 {
		shared.Exit("you must provide a port to run the SSV node stub")
	}

	port, err := strconv.Atoi(os.Args[1])
	if err != nil || port < 0 {
		shared.Exit("the port must be a valid number")
	}

	stub.StartStub(uint(port))
}
