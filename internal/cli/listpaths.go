package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/rom/tarpit-honeypot/internal/config"
)

// cmdListPaths prints every filesystem path the effective config references —
// config file(s), enrichment inputs (tor / threat-intel / OUI), databases
// (GeoIP/ASN + the event store), and the data-dir state — with whether each
// currently exists. The enrichment installer consumes the --json form to
// learn where to place downloaded files.
func cmdListPaths(args []string) error {
	fs := flag.NewFlagSet("list-paths", flag.ContinueOnError)
	cfgPath := fs.String("c", "/etc/tarpit-honeypot/config.yaml", "path to config file")
	asJSON := fs.Bool("json", false, "shortcut for --format json")
	format := fs.String("format", "table", "output format: table | json | tsv")
	category := fs.String("category", "", "filter to one category: config | enrichment | database | state")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *asJSON {
		*format = "json"
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}

	type pathOut struct {
		config.PathRef
		Exists bool `json:"exists"`
	}
	var rows []pathOut
	for _, p := range cfg.Paths(*cfgPath) {
		if *category != "" && p.Category != *category {
			continue
		}
		_, statErr := os.Stat(p.Path)
		rows = append(rows, pathOut{PathRef: p, Exists: statErr == nil})
	}

	switch *format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(rows)
	case "tsv":
		// Stable machine format for scripts (the enrichment installer):
		// category<TAB>key<TAB>access<TAB>exists<TAB>path
		for _, r := range rows {
			access := "read"
			if r.Writable {
				access = "write"
			}
			fmt.Printf("%s\t%s\t%s\t%t\t%s\n", r.Category, r.Key, access, r.Exists, r.Path)
		}
		return nil
	}

	if len(rows) == 0 {
		fmt.Println("(no paths)")
		return nil
	}
	fmt.Printf("%-11s %-26s %-7s %-7s %s\n", "CATEGORY", "KEY", "ACCESS", "EXISTS", "PATH")
	for _, r := range rows {
		access := "read"
		if r.Writable {
			access = "write"
		}
		exists := "yes"
		if !r.Exists {
			exists = "MISSING"
			if r.Writable {
				exists = "pending" // created at runtime
			}
		}
		fmt.Printf("%-11s %-26s %-7s %-7s %s\n", r.Category, r.Key, access, exists, dash(r.Path))
	}
	fmt.Printf("\n%d path(s).\n", len(rows))
	return nil
}
