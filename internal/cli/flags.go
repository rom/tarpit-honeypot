package cli

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/rom/tarpit-honeypot/internal/config"
)

// stringList is a flag.Value collecting repeated --set arguments. Each
// arg is a `key.path=value` pair that gets applied to the loaded YAML
// before validation.
type stringList []string

func (s *stringList) String() string { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error {
	if !strings.Contains(v, "=") {
		return fmt.Errorf("expected key=value, got %q", v)
	}
	*s = append(*s, v)
	return nil
}

// plainList is a repeatable flag.Value that accepts any value (no
// key=value constraint) — used for -c (config paths) and -i (interfaces).
type plainList []string

func (s *plainList) String() string { return strings.Join(*s, ",") }
func (s *plainList) Set(v string) error {
	*s = append(*s, v)
	return nil
}

// commonFlags is what almost every subcommand exposes: -c for config
// path(s), -i for network interface(s), --set for overrides, and the
// loggingFlags block.
type commonFlags struct {
	cfgPaths    plainList
	cfgDefault  string
	ifaces      plainList
	sets        stringList
	interaction string
	log         loggingFlags
}

// register wires up the standard flags on fs. cfgDefault is the default
// config path; pass "" for subcommands that don't take a config. `-c` is
// repeatable — pass it multiple times to combine config files (all hosts
// across all files are used).
func (c *commonFlags) register(fs *flag.FlagSet, cfgDefault string) {
	if cfgDefault != "" {
		c.cfgDefault = cfgDefault
		fs.Var(&c.cfgPaths, "c", "path to config file (repeatable: combine multiple files)")
	}
	fs.Var(&c.ifaces, "i", "network interface to use (repeatable; overrides sensor.interfaces)")
	fs.Var(&c.ifaces, "interface", "alias for -i")
	fs.Var(&c.sets, "set", "override one YAML key as `key.path=value` (repeatable)")
	fs.StringVar(&c.interaction, "interaction-mode", "", "override interaction.mode: low | medium_experimental")
	c.log.register(
		func(p *string, name, def, usage string) { fs.StringVar(p, name, def, usage) },
		func(p *bool, name string, def bool, usage string) { fs.BoolVar(p, name, def, usage) },
	)
}

// paths returns the config paths to load: the repeated -c values, or the
// single default when none were given.
func (c *commonFlags) paths() []string {
	if len(c.cfgPaths) > 0 {
		return c.cfgPaths
	}
	if c.cfgDefault != "" {
		return []string{c.cfgDefault}
	}
	return nil
}

// applyIfaceOverride lets -i / --interface override sensor.interfaces.
func (c *commonFlags) applyIfaceOverride(cfg *config.Config) {
	if len(c.ifaces) > 0 {
		cfg.Sensor.Interfaces = append([]string(nil), c.ifaces...)
	}
}

// overrideSets returns the --set list plus a synthesized
// `interaction.mode=<v>` entry when --interaction-mode was given, so the CLI
// override flows through the normal pre-validation override path (and the
// low-mode guardrail still applies). Pass this to LoadManyWithOverrides.
func (c *commonFlags) overrideSets() stringList {
	if c.interaction == "" {
		return c.sets
	}
	out := append(stringList(nil), c.sets...)
	return append(out, "interaction.mode="+c.interaction)
}

// parseOrUsage runs fs.Parse but treats `-h`/`--help` as a clean exit
// after printing usage to stdout (per POSIX convention; flag.FlagSet's
// default sends help to stderr and exits 2).
func parseOrUsage(fs *flag.FlagSet, args []string) error {
	err := fs.Parse(args)
	if err == flag.ErrHelp {
		fs.SetOutput(os.Stdout)
		fs.Usage()
		fs.SetOutput(os.Stderr)
		// signal "exit cleanly, this isn't an error"
		return errHelp
	}
	return err
}

// errHelp is a sentinel returned by parseOrUsage when the user asked for
// help. Dispatch handles it by returning nil (so the process exits 0).
type errHelpType struct{}

func (errHelpType) Error() string { return "help requested" }

var errHelp = errHelpType{}
