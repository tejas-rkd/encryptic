package main

import (
	"fmt"
	"os"
	"strconv"

	cMan "encryptic/pkg/connectionmanager"
)

func main() {

	lPort, err := strconv.Atoi(os.Args[1])
	if err != nil {
		fmt.Println(err)
	}

	cMan.InitServer(lPort)
}
