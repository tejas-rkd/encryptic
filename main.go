package main

import (
	"os"
	"strconv"

	cMan "encryptic/pkg/connectionmanager"
)

func main() {

	lPort, err := strconv.Atoi(os.Args[1])
	if err != nil {
		panic("Incorrect port value. Please enter appropriate port number (e.g. 5000)")
	}

	cMan.InitServer(lPort)
}
