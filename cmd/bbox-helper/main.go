package main

import (
	"log"
	"os"

	"github.com/moolen/bbox/internal/helperentrypoint"
)

func parseFlags(args []string) (struct{}, error) {
	return struct{}{}, helperentrypoint.ValidateArgs(args)
}

func main() {
	if err := helperentrypoint.Run(os.Args[1:]); err != nil {
		log.Fatal(err)
	}
}
