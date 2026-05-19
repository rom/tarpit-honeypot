package cli

import (
	"flag"
	"fmt"
	"os"
	"strings"
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

// commonFlags is what almost every subcommand exposes: -c for config
// path, --set for overrides, and the loggingFlags block.
type commonFlags struct {
	cfgPath string
	sets    stringList
	log     loggingFlags
}

// register wires up the standard flags on fs. cfgDefault is the default
// config path; pass "" for subcommands that don't take a config.
func (c *commonFlags) register(fs *flag.FlagSet, cfgDefault string) {
	if cfgDefault != "" {
		fs.StringVar(&c.cfgPath, "c", cfgDefault, "path to config file")
	}
	fs.Var(&c.sets, "set", "override one YAML key as `key.path=value` (repeatable)")
	c.log.register(
		func(p *string, name, def, usage string) { fs.StringVar(p, name, def, usage) },
		func(p *bool, name string, def bool, usage string) { fs.BoolVar(p, name, def, usage) },
	)
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
