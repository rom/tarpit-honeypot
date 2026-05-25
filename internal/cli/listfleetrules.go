package cli

import (
	"flag"
	"fmt"
	"strings"

	"github.com/rom/tarpit-honeypot/internal/fleet"
)

// cmdListFleetRules prints the cross-sensor (fleet:*) detector catalog: every
// rule the aggregator's fleet correlator can emit, what it detects, and the
// fleet.* config keys that tune it. Helps an operator discover and configure the
// fleet detectors without reading the source.
func cmdListFleetRules(args []string) error {
	fs := flag.NewFlagSet("list-fleet-rules", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "emit as JSON instead of a table")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cat := fleet.Catalog()
	if *asJSON {
		return writeJSON(cat)
	}
	fmt.Printf("%d cross-sensor detectors (run on an aggregator with ingest: enabled)\n\n", len(cat))
	fmt.Printf("%-30s %s\n", "RULE", "DETECTS")
	for _, r := range cat {
		fmt.Printf("%-30s %s\n", r.ID, r.Summary)
		fmt.Printf("%-30s   config: %s\n", "", strings.Join(r.Config, ", "))
	}
	fmt.Print("\nAll thresholds live under `fleet:` in the config; see docs/config.md.\n")
	return nil
}
