package cli

import (
	"errors"
	"fmt"
	"os"

	"github.com/rom/tarpit-honeypot/internal/version"
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
		{"list-devices", "print the learned-device inventory (devices.json)", cmdListDevices},
		{"init", "write a default config skeleton (run > /etc/.../config.yaml)", cmdInit},
		{"completion", "print shell-completion script (bash | zsh | fish)", cmdCompletion},
		{"help", "long-form help for a subcommand or topic", cmdHelp},
		{"version", "print version info", cmdVersion},
	}

	// Global flags that can appear before any subcommand.
	if len(args) > 0 {
		switch args[0] {
		case "--version", "-V":
			return cmdVersion(nil)
		case "-h", "--help":
			printUsage(cmds)
			return nil
		case "help":
			// "help" with no arg → short usage; with an arg →
			// route through cmdHelp so topics like
			// `help archetypes` work.
			if len(args) == 1 {
				printUsage(cmds)
				return nil
			}
			return cmdHelp(args[1:])
		}
	}

	if len(args) == 0 {
		printUsage(cmds)
		return errors.New("no subcommand given")
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
	fmt.Fprintln(os.Stderr, "usage: tarpit-honeypot [--version|-V] [-h|--help] <subcommand> [flags]")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "subcommands:")
	for _, c := range cmds {
		fmt.Fprintf(os.Stderr, "  %-18s %s\n", c.name, c.desc)
	}
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "common flags (most subcommands):")
	fmt.Fprintln(os.Stderr, "  -c <path>           config file (default /etc/tarpit-honeypot/config.yaml)")
	fmt.Fprintln(os.Stderr, "  --set key=val       override a YAML key (repeatable)")
	fmt.Fprintln(os.Stderr, "  --log-level         debug|info|warn|error (default info)")
	fmt.Fprintln(os.Stderr, "  --log-format        text|json (default text)")
	fmt.Fprintln(os.Stderr, "  --log-file <path>   redirect logs to file (default stderr)")
	fmt.Fprintln(os.Stderr, "  --quiet / --verbose shortcuts for error / debug log level")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "see `tarpit-honeypot <subcommand> -h` for per-subcommand flags")
	fmt.Fprintf(os.Stderr, "version: %s (commit %s)\n", version.Version, version.Commit)
}
