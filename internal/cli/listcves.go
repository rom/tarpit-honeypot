package cli

import (
	"flag"
	"fmt"
	"strings"

	"github.com/rom/tarpit-honeypot/internal/cve"
)

// cmdListCVEs prints the in-source CVE catalog the sensor uses for
// vulnerable-banner emulation and exploit-attempt recognition. The DET
// column marks records that carry exploit signatures (MatchPayload flags
// a live attempt); the rest are advisory-only (banner / patch-level).
func cmdListCVEs(args []string) error {
	fs := flag.NewFlagSet("list-cves", flag.ContinueOnError)
	service := fs.String("service", "", "filter by service/handler (e.g. http, fortinet, s7)")
	asJSON := fs.Bool("json", false, "emit as JSON instead of a table")
	if err := fs.Parse(args); err != nil {
		return err
	}

	all := cve.All()
	var rows []cve.Record
	for _, r := range all {
		if *service != "" && !strings.EqualFold(r.Service, *service) {
			continue
		}
		rows = append(rows, r)
	}

	if *asJSON {
		return writeJSON(rows)
	}

	if len(rows) == 0 {
		fmt.Println("(no matching CVEs)")
		return nil
	}
	fmt.Printf("%-18s %5s %-16s %-3s %s\n", "ID", "CVSS", "SERVICE", "DET", "NAME")
	for _, r := range rows {
		det := "-"
		if r.Detectable() {
			det = "yes"
		}
		fmt.Printf("%-18s %5.1f %-16s %-3s %s\n", r.ID, r.CVSS, dash(r.Service), det, r.Name)
	}
	fmt.Printf("\n%d CVE(s). DET=yes means an exploit attempt is recognized live.\n", len(rows))
	return nil
}
