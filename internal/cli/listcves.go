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
	cweMode := fs.Bool("cwe", false, "list the CWE weakness-class catalog (id, CVE count, name) instead")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *cweMode {
		cwes := cve.CWEs()
		if *asJSON {
			return writeJSON(cwes)
		}
		fmt.Printf("%-10s %5s  %s\n", "CWE", "CVES", "WEAKNESS CLASS")
		for _, c := range cwes {
			fmt.Printf("%-10s %5d  %s\n", c.ID, c.Count, dash(c.Name))
		}
		fmt.Printf("\n%d CWE weakness class(es) referenced by the CVE catalog.\n", len(cwes))
		return nil
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
	fmt.Printf("%-18s %5s %5s %-16s %-3s %s\n", "ID", "CVSS", "EPSS", "SERVICE", "DET", "NAME")
	for _, r := range rows {
		det := "-"
		if r.Detectable() {
			det = "yes"
		}
		epss := "-"
		if r.EPSS > 0 {
			epss = fmt.Sprintf("%.2f", r.EPSS)
		}
		fmt.Printf("%-18s %5.1f %5s %-16s %-3s %s\n", r.ID, r.CVSS, epss, dash(r.Service), det, r.Name)
	}
	fmt.Printf("\n%d CVE(s). DET=yes means a live exploit attempt is recognized; "+
		"--json adds CWE/CPE/EPSS.\n", len(rows))
	return nil
}
