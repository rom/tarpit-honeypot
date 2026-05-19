package cli

import (
	"errors"
	"fmt"
	"os"
)

type command struct {
	name string
	desc string
	run  func(args []string) error
}

func Dispatch(args []string) error {
	cmds := []command{
		{"run", "start the sensor (listeners + sinks)", cmdRun},
		{"validate-config", "parse and validate a config file (with optional --diff)", cmdValidate},
		{"show-config", "print the effective post-defaults config as YAML", cmdShowConfig},
		{"test-alert", "emit a synthetic event through configured channels", cmdTestAlert},
		{"list-events", "tail / query events from the local JSON log or sqlite", cmdListEvents},
		{"gen-token", "print an unguessable canary token (dns | url | hex)", cmdGenToken},
		{"export-pcap", "copy one event's per-connection pcap out of the captures dir", cmdExportPcap},
		{"list-honeynets", "print the configured artificial networks + hosts + services", cmdListHoneynets},
		{"version", "print version info", cmdVersion},
	}

	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		printUsage(cmds)
		if len(args) == 0 {
			return errors.New("no subcommand given")
		}
		return nil
	}

	for _, c := range cmds {
		if c.name == args[0] {
			return c.run(args[1:])
		}
	}
	printUsage(cmds)
	return fmt.Errorf("unknown subcommand %q", args[0])
}

func printUsage(cmds []command) {
	fmt.Fprintln(os.Stderr, "usage: tarpit-honeypot <subcommand> [flags]")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "subcommands:")
	for _, c := range cmds {
		fmt.Fprintf(os.Stderr, "  %-18s %s\n", c.name, c.desc)
	}
}
