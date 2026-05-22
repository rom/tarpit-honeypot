package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/rom/tarpit-honeypot/internal/config"
)

// cmdListUnavailableCapabilities prints the high-interaction / experimental
// capture features that are NOT (fully) available under the active
// interaction config, with the reason for each — so an operator can see
// exactly which signals the deployment cannot produce instead of inferring
// it from the docs. Honors -c, --set and --interaction-mode.
func cmdListUnavailableCapabilities(args []string) error {
	fs := flag.NewFlagSet("list-unavailable-capabilities", flag.ContinueOnError)
	var f commonFlags
	f.register(fs, "/etc/tarpit-honeypot/config.yaml")
	asJSON := fs.Bool("json", false, "emit JSON instead of a table")
	if err := parseOrUsage(fs, args); err != nil {
		if err == errHelp {
			return nil
		}
		return err
	}

	// Reflect the deployment's interaction config when a config loads cleanly;
	// otherwise (no/invalid config file) fall back to defaults + the
	// --interaction-mode flag so the command always works out of the box.
	in := config.Interaction{}
	if cfg, err := config.LoadManyWithOverrides(f.paths(), f.overrideSets()); err == nil {
		in = cfg.Interaction
	} else {
		in.Mode = f.interaction
		in.ApplyDefaults()
	}

	caps := in.UnavailableCapabilities()

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(map[string]any{"interaction_mode": in.Mode, "capabilities": caps})
	}

	fmt.Printf("interaction.mode = %s\n", in.Mode)
	fmt.Printf("unavailable / experimental capabilities (%d):\n\n", len(caps))
	fmt.Printf("  %-34s %-12s %s\n", "CAPABILITY", "STATUS", "REASON")
	for _, c := range caps {
		fmt.Printf("  %-34s %-12s %s\n", c.Name, c.Status, c.Reason)
	}
	fmt.Println()
	fmt.Println("status: disabled = enableable via config · experimental = best-effort/incomplete")
	fmt.Println("        locked   = forbidden in low mode  · unavailable = not implemented/infeasible")
	return nil
}
