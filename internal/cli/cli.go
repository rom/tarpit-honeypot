package cli

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/rom/tarpit-honeypot/internal/version"
)

type command struct {
	name string
	desc string
	run  func(args []string) error
}

// globalValueFlags are the space-form (`-c path`) flags that may appear
// before the subcommand; their following token is a value, not the
// subcommand. (`=`-form `-c=path` is a single token and needs no entry.)
var globalValueFlags = map[string]bool{
	"-c": true, "-i": true, "--interface": true, "--set": true,
	"--interaction-mode": true,
	"--log-level":        true, "--log-format": true, "--log-file": true,
}

func Dispatch(args []string) error {
	cmds := []command{
		{"run", "start the sensor (listeners + sinks)", cmdRun},
		{"validate-config", "parse and validate a config file (with optional --diff)", cmdValidate},
		{"show-config", "print the effective post-defaults config as YAML", cmdShowConfig},
		{"test-alert", "emit a synthetic event through configured channels", cmdTestAlert},
		{"list-events", "tail / query events from the local JSON log or sqlite", cmdListEvents},
		{"gen-token", "print an unguessable canary token (dns | url | hex | ssrf)", cmdGenToken},
		{"export-pcap", "copy one event's per-connection pcap out of the captures dir", cmdExportPcap},
		{"list-honeynets", "print the configured artificial networks + hosts + services", cmdListHoneynets},
		{"list-devices", "print the learned-device inventory (devices.json)", cmdListDevices},
		{"list-paths", "print all config / enrichment / database / state file paths (+ --json)", cmdListPaths},
		{"list-archetypes", "print the device/OS archetype catalog (name for detail)", cmdListArchetypes},
		{"list-handlers", "print the protocol handlers valid in a listener", cmdListHandlers},
		{"list-archeservices", "print the service roles (webserver, adserver, …)", cmdListArcheservices},
		{"list-cves", "print the CVE catalog (emulation + exploit detection)", cmdListCVEs},
		{"list-techniques", "print the MITRE ATT&CK / D3FEND coverage map", cmdListTechniques},
		{"list-fleet-rules", "print the cross-sensor (fleet:*) detector catalog", cmdListFleetRules},
		{"list-unavailable-capabilities", "print disabled / infeasible high-interaction features", cmdListUnavailableCapabilities},
		{"export-iocs", "export fleet IOCs from the store (stix | csv | txt | json)", cmdExportIOCs},
		{"identify", "fingerprint a UA / path / ssh-id / ja3 / payload offline", cmdIdentify},
		{"jarm", "actively probe a TLS server and print its JARM fingerprint", cmdJARM},
		{"reset-db", "empty the local event store / device inventory / captures", cmdResetDB},
		{"init", "write a default config skeleton (run > /etc/.../config.yaml)", cmdInit},
		{"completion", "print shell-completion script (bash | zsh | fish)", cmdCompletion},
		{"help", "long-form help for a subcommand or topic", cmdHelp},
		{"version", "print version info", cmdVersion},
	}
	cmdSet := map[string]command{}
	for _, c := range cmds {
		cmdSet[c.name] = c
	}

	// --version / -V is informational and accepted in any position.
	for _, a := range args {
		if a == "--version" || a == "-V" {
			return cmdVersion(nil)
		}
	}

	// Locate the subcommand token — flags (and their values) may precede it,
	// so `-c cfg.yaml run` and `run -c cfg.yaml` are equivalent.
	subIdx := findSubcommand(args, cmdSet)
	if subIdx < 0 {
		for _, a := range args {
			if a == "-h" || a == "--help" || a == "help" {
				printUsage(cmds)
				return nil
			}
		}
		printUsage(cmds)
		if len(args) == 0 {
			return errors.New("no subcommand given")
		}
		return fmt.Errorf("unknown subcommand %q", args[0])
	}

	name := args[subIdx]
	// All other tokens (flags from before AND after the subcommand) go to
	// the subcommand's own flag parser, preserving order.
	subArgs := append(append([]string(nil), args[:subIdx]...), args[subIdx+1:]...)

	if name == "help" {
		if len(subArgs) == 0 {
			printUsage(cmds)
			return nil
		}
		return cmdHelp(subArgs)
	}
	return cmdSet[name].run(subArgs)
}

// findSubcommand returns the index of the first arg that names a subcommand,
// skipping leading flags and the values of space-form global value-flags.
// Returns -1 when no subcommand is present.
func findSubcommand(args []string, cmdSet map[string]command) int {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if strings.HasPrefix(a, "-") {
			// A space-form value-flag consumes the next token as its value.
			if globalValueFlags[a] && i+1 < len(args) {
				i++
			}
			continue
		}
		if _, ok := cmdSet[a]; ok {
			return i
		}
		// A non-flag, non-command token (e.g. an unrecognized value) — keep
		// scanning for the subcommand.
	}
	return -1
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
