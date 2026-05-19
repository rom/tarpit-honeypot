package cli

import (
	"fmt"

	"github.com/rom/tarpit-honeypot/internal/version"
)

func cmdVersion(_ []string) error {
	fmt.Printf("tarpit-honeypot %s (commit %s, built %s)\n",
		version.Version, version.Commit, version.BuildDate)
	return nil
}
