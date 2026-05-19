package main

import (
	"fmt"
	"os"

	"github.com/rom/tarpit-honeypot/internal/cli"
)

func main() {
	if err := cli.Dispatch(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "tarpit-honeypot:", err)
		os.Exit(1)
	}
}
