package cli

import (
	"flag"
	"fmt"
	"io"
	"os"

	"gopkg.in/yaml.v3"

	"github.com/rom/tarpit-honeypot/internal/config"
)

// cmdInit writes the default config — i.e. a Config struct with all the
// applyDefaults values filled in — to stdout (or -o file). Operators use
// this to scaffold a fresh /etc/tarpit-honeypot/config.yaml instead of
// copying from configs/.
func cmdInit(args []string) error {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	out := fs.String("o", "-", "output file; '-' = stdout")
	if err := parseOrUsage(fs, args); err != nil {
		if err == errHelp {
			return nil
		}
		return err
	}
	var defaultCfg config.Config
	// Reuse the Load defaults by going through a temp YAML round-trip.
	// Easier than maintaining a parallel "defaults" struct.
	apply := func(c *config.Config) {
		// Trigger applyDefaults() via Load on an empty buffer. We
		// inline-marshal here to avoid the Load file-reading path.
	}
	apply(&defaultCfg)
	// Build a config matching what Load() would produce for an empty file.
	// We rely on config.Load with a temp empty file to populate defaults
	// cleanly, then marshal back.
	tmp, err := os.CreateTemp("", "tarpit-init-*.yaml")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	_ = tmp.Close()
	if err := os.WriteFile(tmp.Name(), []byte("{}\n"), 0o600); err != nil {
		return err
	}
	cfg, err := config.LoadDefaultsOnly(tmp.Name())
	if err != nil {
		return err
	}
	var w io.Writer = os.Stdout
	if *out != "-" {
		f, err := os.Create(*out)
		if err != nil {
			return err
		}
		defer f.Close()
		w = f
	}
	fmt.Fprintln(w, "# tarpit-honeypot default configuration.")
	fmt.Fprintln(w, "# Edit to taste; validate with `tarpit-honeypot validate-config -c <path>`.")
	fmt.Fprintln(w, "")
	enc := yaml.NewEncoder(w)
	enc.SetIndent(2)
	if err := enc.Encode(cfg); err != nil {
		return err
	}
	return enc.Close()
}
