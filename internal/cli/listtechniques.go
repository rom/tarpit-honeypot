package cli

import (
	"flag"
	"fmt"
	"sort"
	"strings"

	"github.com/rom/tarpit-honeypot/internal/mitre"
)

// cmdListTechniques prints the sensor's static MITRE ATT&CK coverage:
// every rule / handler / anomaly marker mapped to its ATT&CK techniques
// + tactics, annotated with the D3FEND countermeasures the router stamps
// alongside. A SOC uses this to audit detection coverage and to wire
// ATT&CK-navigator layers without reading the source.
func cmdListTechniques(args []string) error {
	fs := flag.NewFlagSet("list-techniques", flag.ContinueOnError)
	kind := fs.String("kind", "", "filter by kind: rule | handler | anomaly")
	asJSON := fs.Bool("json", false, "emit as JSON instead of a table")
	defenses := fs.Bool("defenses", false, "print the D3FEND countermeasure legend (id -> name) and exit")
	if err := fs.Parse(args); err != nil {
		return err
	}
	switch *kind {
	case "", "rule", "handler", "anomaly":
	default:
		return fmt.Errorf("--kind must be rule, handler, or anomaly, got %q", *kind)
	}

	if *defenses {
		cat := mitre.DefenseCatalog()
		if *asJSON {
			return writeJSON(cat)
		}
		ids := make([]string, 0, len(cat))
		for id := range cat {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		fmt.Printf("%-10s %s\n", "D3FEND", "COUNTERMEASURE")
		for _, id := range ids {
			fmt.Printf("%-10s %s\n", id, cat[id])
		}
		fmt.Printf("\n%d D3FEND countermeasure(s) mapped.\n", len(ids))
		return nil
	}

	all := mitre.Coverage()
	var rows []mitre.CoverageEntry
	for _, e := range all {
		if *kind != "" && e.Kind != *kind {
			continue
		}
		rows = append(rows, e)
	}

	if *asJSON {
		return writeJSON(rows)
	}

	fmt.Printf("%-8s %-30s %-26s %s\n", "KIND", "KEY", "ATT&CK", "D3FEND")
	for _, e := range rows {
		fmt.Printf("%-8s %-30s %-26s %s\n",
			e.Kind, trunc(e.Key, 30), strings.Join(e.Techniques, ","), strings.Join(e.Defenses, ","))
	}
	fmt.Printf("\n%d mapping(s).\n", len(rows))
	return nil
}

// trunc shortens s to n runes with an ellipsis so wide keys don't break
// table alignment.
func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n <= 1 {
		return s[:n]
	}
	return s[:n-1] + "…"
}
