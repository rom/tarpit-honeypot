package cli

import (
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/rom/tarpit-honeypot/internal/archetype"
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
	if topic == "archetypes" {
		printArchetypes()
		return nil
	}
	if doc, ok := helpDocs[topic]; ok {
		fmt.Print(doc)
		return nil
	}
	fmt.Fprintf(os.Stderr, "no help topic %q\n", topic)
	printAllHelp()
	return fmt.Errorf("unknown topic")
}

// printArchetypes lists every shipped archetype and the banner values
// it pins. Useful as a quick "what do my SSH / HTTP banners look like
// under sensor.archetype: debian 12" reference.
func printArchetypes() {
	fmt.Println(`archetypes — OS / device-shaped fingerprint profiles

Set sensor.archetype (or listener.archetype, or per-host archetype) to
one of the names below. Every fingerprint-bearing handler reports
values consistent with a stock install / device-default config of
that OS / device, so a scanner can't catch the sensor by spotting
mismatches.

What each archetype controls:
  - SSH / HTTP / FTP / Telnet / SMTP / MySQL banner strings
  - SNMP MIB-2 identity (sysDescr / sysObjectID / sysName / ifTable)
  - MAC vendor OUI (Moxa 00:90:E8, Siemens 28:63:36, ...)
  - CLI prompt + login prompt for the post-login shell engagement
  - Web UI title + body for the HTTP handler
  - LLDP system-description / capabilities advertised on the segment
  - Default service list (informational)

Without an archetype, banners come from the v1.0 deployment-id-keyed
variant pool (still unique-per-sensor, just not pinned to a specific
distribution).

NAMES (case- and separator-insensitive)`)
	for _, n := range archetype.Names() {
		fmt.Printf("    %s\n", n)
	}
	fmt.Println()
	fmt.Println(`USAGE
    sensor:
      archetype: debian 12
    listeners:
      - id: ssh-bait
        archetype: red hat enterprise linux 9   # overrides sensor
        proto: tcp
        bind: 0.0.0.0:22
        handler: ssh
    honeynets:
      - id: corp-prod
        hosts:
          - ip: 10.99.1.10
            archetype: ubuntu 24.04 lts          # overrides listener
            services:
              - { port: 22, handler: ssh }

ORDER OF PRECEDENCE (most specific wins)
    honeynet host > listener > sensor > "no archetype" (identity pool)`)
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
                         Repeatable: pass -c twice+ to COMBINE files (every
                         listener/honeynet across all files is used; scalar
                         config takes the last file's value). run / validate-
                         config / show-config.
    -i, --interface <if> Network interface to use (repeatable). Overrides
                         sensor.interfaces: default for the AF_PACKET layer +
                         pins wildcard listener binds to the interface IP.
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
	fmt.Println(`TOPICS
    archetypes         The OS / device-shaped fingerprint profiles you can pin.

Use ` + "`tarpit-honeypot help <subcommand>`" + ` for the full topic.`)
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
    tarpit-honeypot gen-token --type=dns|url|hex|ssrf|doc
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

	"list-devices": `list-devices — print the learned-device inventory

SYNOPSIS
    tarpit-honeypot list-devices -c <config> [--json]

DESCRIPTION
    Read-only dump of <data_dir>/devices.json — the passive device
    inventory the sniffer + listeners build over time (IP / MAC /
    vendor / hostname / class / first+last seen), with the configured
    allow-list applied. Snapshot a baseline with --json.

EXAMPLES
    tarpit-honeypot list-devices -c cfg.yaml
    tarpit-honeypot list-devices -c cfg.yaml --json > baseline.json
`,

	"list-archetypes": `list-archetypes — print the device/OS archetype catalog

SYNOPSIS
    tarpit-honeypot list-archetypes [--json] [<name>]

DESCRIPTION
    With no argument, lists every shipped archetype (the canonical name
    you put in sensor.archetype, its family, service + CVE counts). With
    a name (canonical or pretty DisplayName), prints that archetype's
    full fingerprint: banners, SNMP identity, ICMP TTL, advertised CVEs,
    and default services. Reads only the in-source catalog — no config.

EXAMPLES
    tarpit-honeypot list-archetypes
    tarpit-honeypot list-archetypes debian-12
    tarpit-honeypot list-archetypes --json beckhoff-cx
`,

	"list-handlers": `list-handlers — print the protocol handlers valid in a listener

SYNOPSIS
    tarpit-honeypot list-handlers [--proto tcp|udp]

DESCRIPTION
    Print every value accepted in a listener's handler: field, split by
    transport. Sourced from the same whitelist the config validator
    enforces, so it never drifts from what ` + "`run`" + ` will accept.

EXAMPLES
    tarpit-honeypot list-handlers
    tarpit-honeypot list-handlers --proto udp
`,

	"list-archeservices": `list-archeservices — print the service roles

SYNOPSIS
    tarpit-honeypot list-archeservices [<role>]

DESCRIPTION
    Print the built-in service roles (webserver, ftpserver, printserver,
    fileserver, ldapserver, adserver, dbserver, mailserver, …) and the
    port/proto/handler set each one stands up. Use a role in an
    archeservices: config entry together with an archetype: so the
    expanded listeners answer with the right software identity.

EXAMPLES
    tarpit-honeypot list-archeservices
    tarpit-honeypot list-archeservices adserver
`,

	"list-cves": `list-cves — print the CVE catalog

SYNOPSIS
    tarpit-honeypot list-cves [--service <handler>] [--json]

DESCRIPTION
    Dump the in-source CVE catalog used for vulnerable-banner emulation
    and exploit-attempt recognition. The DET column marks records whose
    exploit signature is recognized live (MatchPayload); the rest are
    advisory-only. Filter to one service/handler with --service.

EXAMPLES
    tarpit-honeypot list-cves
    tarpit-honeypot list-cves --service fortinet
`,

	"list-techniques": `list-techniques — print the MITRE ATT&CK / D3FEND coverage map

SYNOPSIS
    tarpit-honeypot list-techniques [--kind rule|handler|anomaly] [--json]

DESCRIPTION
    Print every static rule / handler / anomaly → ATT&CK technique +
    tactic mapping the router stamps on events, annotated with the
    D3FEND countermeasures for each. Audit detection coverage or build
    ATT&CK-navigator layers without reading the source.

EXAMPLES
    tarpit-honeypot list-techniques
    tarpit-honeypot list-techniques --kind anomaly
`,

	"identify": `identify — fingerprint a captured signal offline

SYNOPSIS
    tarpit-honeypot identify [--ua S] [--path S] [--method M]
        [--headers a,b] [--ssh S] [--ja3 S] [--payload S] [--handler H]

DESCRIPTION
    Run the sensor's offline fingerprint engine over signals you supply
    and print the same verdict a live listener would attach: tool /
    scanner name, automation flag, and any CVE exploit signature found
    in --payload. A tuning / triage aid — no network, no config.

EXAMPLES
    tarpit-honeypot identify --ua "sqlmap/1.7"
    tarpit-honeypot identify --ssh SSH-2.0-Go
    tarpit-honeypot identify --payload '${jndi:ldap://x/a}' --handler http
`,

	"reset-db": `reset-db — empty the local databases / artifact stores

SYNOPSIS
    tarpit-honeypot reset-db [-c <config> | --data-dir <dir>] [scope flags] [--yes]

DESCRIPTION
    Clears state under the sensor's data_dir. Default scope is the event
    store (events.db + the JSON event logs). The sensor identity
    (.deployment-id) and TLS certs are always preserved. Destructive, so it
    DRY-RUNS unless you pass --yes/-y. Stop the sensor first (deleting an
    open SQLite file is unsafe).

SCOPE FLAGS
    --all         events + devices + captures + payloads + sessions + state
    --devices     also clear devices.json (learned-device inventory)
    --captures    also clear captures/ (per-connection pcaps)
    --payloads    also clear payloads/ (harvested malware/shellcode)
    --sessions    also clear sessions/ (recorded shell casts)
    --state       also clear the persisted correlator state
    --data-dir D  operate on D directly (skip loading the config)

EXAMPLES
    tarpit-honeypot reset-db -c cfg.yaml                 # dry-run (events)
    tarpit-honeypot reset-db -c cfg.yaml --yes           # clear the event store
    tarpit-honeypot reset-db --data-dir /var/lib/... --all --yes
`,

	"rotate-db": `rotate-db — archive (gzip) the event database, optionally start fresh

SYNOPSIS
    tarpit-honeypot rotate-db [-c <config> | --data-dir <dir>] [--out <file.gz>]
                              [--reset --yes]

DESCRIPTION
    Writes a consistent, compacted, gzip-compressed copy of the sqlite event
    store (events.db) to an archive — a "VACUUM INTO" snapshot, so it is safe
    even while the sensor is writing (no need to copy the -wal/-shm sidecars).
    Use it to keep old logs off-box on a schedule.

    With --reset --yes it then empties the live event table and VACUUMs, so the
    sensor continues with a fresh, small database (classic log rotation). The
    archive is always kept. Stop the sensor before using --reset.

FLAGS
    --out F        archive path (default: <data_dir>/events-<UTC ts>.db.gz)
    --reset        after archiving, empty the live event store and VACUUM
    --yes / -y     required with --reset to actually empty the store
    --data-dir D   operate on D directly (skip loading the config)

EXAMPLES
    tarpit-honeypot rotate-db -c cfg.yaml
    tarpit-honeypot rotate-db -c cfg.yaml --out /backups/events-$(date +%F).db.gz
    tarpit-honeypot rotate-db -c cfg.yaml --reset --yes   # archive then start fresh
`,

	"prune-db": `prune-db — delete the oldest events to free space

SYNOPSIS
    tarpit-honeypot prune-db [-c <config> | --data-dir <dir>]
                             (--keep-days N | --keep-rows N | --max-mb N)
                             [--vacuum] [--yes]

DESCRIPTION
    Drops the oldest events from the sqlite store to reclaim disk, choosing the
    rows to delete one of three ways (mutually exclusive). DRY-RUNS unless --yes
    is given, reporting how many rows would go. By default it VACUUMs afterwards
    so the freed pages return to the filesystem. Stop the sensor first (VACUUM
    needs exclusive access).

    For continuous, automatic retention prefer the config
    sensor.disk.retention_days / sensor.disk.sqlite_mb knobs; prune-db is the
    manual, one-shot reclaim.

MODES (choose one)
    --keep-days N  delete events older than N days
    --keep-rows N  keep only the newest N events, delete the rest
    --max-mb N     delete oldest events (in batches) until the DB is under N MB

FLAGS
    --vacuum       VACUUM after deleting (default true)
    --yes / -y     actually delete (without this it is a dry-run)
    --data-dir D   operate on D directly (skip loading the config)

EXAMPLES
    tarpit-honeypot prune-db -c cfg.yaml --keep-days 30          # dry-run
    tarpit-honeypot prune-db -c cfg.yaml --keep-days 30 --yes
    tarpit-honeypot prune-db -c cfg.yaml --keep-rows 1000000 --yes
    tarpit-honeypot prune-db -c cfg.yaml --max-mb 200 --yes
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
