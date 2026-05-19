package cli

import (
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
)

// cmdHelp prints extensive usage for one subcommand (or all of them if
// invoked without an argument). Goes deeper than the per-subcommand
// `-h`, which only enumerates the flag set — `help <subcommand>` adds
// a behavior summary, common flags, and examples.
func cmdHelp(args []string) error {
	fs := flag.NewFlagSet("help", flag.ContinueOnError)
	if err := parseOrUsage(fs, args); err != nil {
		if err == errHelp {
			return nil
		}
		return err
	}
	if fs.NArg() == 0 {
		printAllHelp()
		return nil
	}
	topic := fs.Arg(0)
	if doc, ok := helpDocs[topic]; ok {
		fmt.Print(doc)
		return nil
	}
	fmt.Fprintf(os.Stderr, "no help topic %q\n", topic)
	printAllHelp()
	return fmt.Errorf("unknown topic")
}

func printAllHelp() {
	fmt.Println(`tarpit-honeypot — deception sensor

USAGE
    tarpit-honeypot [global flags] <subcommand> [subcommand flags]
    tarpit-honeypot help <subcommand>

GLOBAL FLAGS
    --version, -V        Print version + commit + build date.
    --help, -h, help     Show this listing or a per-subcommand topic.

COMMON FLAGS (most subcommands)
    -c <path>            Config file (default /etc/tarpit-honeypot/config.yaml).
    --set key.path=val   Override one YAML key (repeatable). Booleans /
                         ints / floats / strings auto-detected.
    --log-level          debug | info | warn | error (default info).
    --log-format         text | json (default text).
    --log-file <path>    Redirect logs to file (default stderr).
    --quiet              Shortcut for --log-level=error.
    --verbose            Shortcut for --log-level=debug.

CONFIG OVERRIDE LAYERING
    1. Base YAML file from -c.
    2. Sibling conf.d/*.yaml in lexical order, deep-merged.
    3. TARPIT_<KEY_PATH> env vars (TARPIT_SENSOR_NAME=foo). Use __
       to escape a real underscore inside a key segment.
    4. --set key.path=value (after env vars; wins).

SUBCOMMANDS`)
	names := make([]string, 0, len(helpDocs))
	for name := range helpDocs {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, n := range names {
		short := strings.SplitN(helpDocs[n], "\n", 2)[0]
		fmt.Printf("    %-18s %s\n", n, strings.TrimPrefix(short, n+" — "))
	}
	fmt.Println()
	fmt.Println("Use `tarpit-honeypot help <subcommand>` for the full topic.")
}

// helpDocs holds the long-form usage for every subcommand. First line of
// each entry is the one-liner shown in the index. Keep the content in
// sync with docs/cli.md — the docs file is the source of truth for
// detailed flag tables; this is a quick offline reference.
var helpDocs = map[string]string{
	"run": `run — start the sensor (listeners + sinks)

SYNOPSIS
    tarpit-honeypot run -c <config> [--dry-run] [common flags]

DESCRIPTION
    Bring up the sensor in the foreground. Returns when SIGINT/SIGTERM
    arrives. Responds to SIGHUP by reloading the config: channels /
    routes / allowlist / dedup / correlator thresholds / canary lists
    hot-swap, listeners restart per-id, sensor.* changes warn.

FLAGS
    --dry-run    Load + validate config, construct the sensor, exit
                 without binding any listeners. Useful for CI.

EXAMPLES
    tarpit-honeypot run -c /etc/tarpit-honeypot/config.yaml
    tarpit-honeypot run -c cfg.yaml --dry-run --set sensor.name=ci
    tarpit-honeypot run -c cfg.yaml --log-format=json --log-level=debug
`,

	"validate-config": `validate-config — parse and validate a config file

SYNOPSIS
    tarpit-honeypot validate-config -c <config> [--diff <other.yaml>]

DESCRIPTION
    Apply defaults + run all validation rules. With --diff, classify
    each change between two configs as hot-reloadable vs restart-
    required (same logic the SIGHUP path uses).

EXAMPLES
    tarpit-honeypot validate-config -c cfg.yaml
    tarpit-honeypot validate-config -c current.yaml --diff proposed.yaml
`,

	"show-config": `show-config — print the effective post-defaults config

SYNOPSIS
    tarpit-honeypot show-config -c <config>

DESCRIPTION
    Dump the merged config (base + conf.d + env + --set) with all
    defaults filled in. Secrets stay as env var names so the output
    is safe to paste in tickets.

EXAMPLES
    tarpit-honeypot show-config -c cfg.yaml | less
    TARPIT_SENSOR_NAME=demo tarpit-honeypot show-config -c cfg.yaml
`,

	"test-alert": `test-alert — inject a synthetic event through the routing pipeline

SYNOPSIS
    tarpit-honeypot test-alert -c <config> [--severity high] [--note "..."]

DESCRIPTION
    Useful right after wiring a new outbound channel (Twilio / SNS /
    webhook): produces a synthetic event_id=synthetic:test-alert that
    goes through the same dedup / allowlist / rate-limit logic as a
    real event.

EXAMPLES
    tarpit-honeypot test-alert -c cfg.yaml --severity critical
`,

	"list-events": `list-events — tail / query the local event store

SYNOPSIS
    tarpit-honeypot list-events -c <config> [--since 24h]
        [--source <ip>] [--rule <id>] [--limit N]

DESCRIPTION
    Prefer SQLite when <data_dir>/events.db exists; fall back to
    scanning JSONL files for tripwire-only configs.

EXAMPLES
    tarpit-honeypot list-events -c cfg.yaml --since 5m
    tarpit-honeypot list-events -c cfg.yaml --rule correlate:port_scan
    tarpit-honeypot list-events -c cfg.yaml --source 198.51.100.42
`,

	"gen-token": `gen-token — generate unguessable canary tokens

SYNOPSIS
    tarpit-honeypot gen-token --type=dns|url|hex
        [--label LBL] [--bits N] [--domain D]

DESCRIPTION
    Three shapes: dns (a hostname under --domain), url (path under
    /__canary__/), or hex (just the random bytes). Default 64 bits.

EXAMPLES
    tarpit-honeypot gen-token --type=dns --label=prod-cdb
    tarpit-honeypot gen-token --type=url --bits=128
    tarpit-honeypot gen-token --type=hex --bits=256
`,

	"export-pcap": `export-pcap — copy one event's pcap out of the captures dir

SYNOPSIS
    tarpit-honeypot export-pcap -c <config> --event <id> [-o file|-]

DESCRIPTION
    Read-only; never touches sensor state. Only events from TCP
    listeners with capture: true have a pcap. The file is a
    synthesized libpcap (DLT_RAW, IPv4+TCP headers, tracked seq
    numbers) — Wireshark loads it directly.

EXAMPLES
    tarpit-honeypot export-pcap -c cfg.yaml --event abc123 -o /tmp/x.pcap
    tarpit-honeypot list-events -c cfg.yaml --limit 1 --rule listener:ssh-bait
`,

	"list-honeynets": `list-honeynets — print the configured artificial-network topology

SYNOPSIS
    tarpit-honeypot list-honeynets -c <config>

DESCRIPTION
    One network per header line, indented host listing with per-host
    derived MAC + identity seed. Confirms each virtual machine is
    presenting a distinct fingerprint.

EXAMPLES
    tarpit-honeypot list-honeynets -c cfg.yaml
`,

	"init": `init — write a default config skeleton

SYNOPSIS
    tarpit-honeypot init [-o file]

DESCRIPTION
    Print the post-defaults Config struct as YAML. Useful for
    scaffolding a fresh deployment.

EXAMPLES
    tarpit-honeypot init > /etc/tarpit-honeypot/config.yaml
    tarpit-honeypot init -o cfg.yaml
`,

	"completion": `completion — print shell-completion script

SYNOPSIS
    tarpit-honeypot completion bash|zsh|fish

EXAMPLES
    tarpit-honeypot completion bash > /etc/bash_completion.d/tarpit-honeypot
    tarpit-honeypot completion zsh  > "${fpath[1]}/_tarpit-honeypot"
    tarpit-honeypot completion fish > ~/.config/fish/completions/tarpit-honeypot.fish
`,

	"version": `version — print version, commit, build date

SYNOPSIS
    tarpit-honeypot version
    tarpit-honeypot --version
    tarpit-honeypot -V

DESCRIPTION
    Three forms all print the same single-line summary.
`,

	"help": `help — show help for a subcommand or topic

SYNOPSIS
    tarpit-honeypot help [<topic>]

DESCRIPTION
    With no argument, prints the subcommand index + common flags.
    With a subcommand name, prints the long-form topic.

EXAMPLES
    tarpit-honeypot help
    tarpit-honeypot help run
    tarpit-honeypot help list-events
`,
}
