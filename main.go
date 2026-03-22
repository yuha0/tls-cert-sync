package main

import (
	"os"

	"github.com/tlscertsync/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
