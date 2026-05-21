package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/rom/tarpit-honeypot/internal/archetype"
)

// cmdListArchetypes prints the built-in device/OS archetype catalog.
// With no positional argument it lists every archetype (the canonical
// name you put in `sensor.archetype:` plus a one-line summary); with a
// name it prints the full fingerprint of that one archetype.
//
// It reads only the in-source catalog — no config, no network — so it's
// safe to run anywhere to discover what the sensor can impersonate.
func cmdListArchetypes(args []string) error {
	fs := flag.NewFlagSet("list-archetypes", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "emit as JSON instead of a table")
	if err := fs.Parse(args); err != nil {
		return err
	}

	// `list-archetypes [--json] <name>` → detail for one archetype.
	if name := fs.Arg(0); name != "" {
		p := archetype.Find(name)
		if p == nil {
			return fmt.Errorf("unknown archetype %q (try `tarpit-honeypot list-archetypes`)", name)
		}
		if *asJSON {
			return writeJSON(archetypeView(p))
		}
		printArchetypeDetail(p)
		return nil
	}

	all := archetype.All()
	if *asJSON {
		views := make([]archetypeSummary, 0, len(all))
		for _, p := range all {
			views = append(views, archetypeSummary{
				Name: p.Name, DisplayName: p.DisplayName, Family: p.Family,
				Services: len(p.DefaultServices()), CVEs: len(p.VulnCVEs()),
			})
		}
		return writeJSON(views)
	}

	fmt.Printf("%-30s %-10s %4s %4s  %s\n", "NAME", "FAMILY", "SVCS", "CVES", "DISPLAY NAME")
	for _, p := range all {
		fmt.Printf("%-30s %-10s %4d %4d  %s\n",
			dash(p.Name), dash(p.Family), len(p.DefaultServices()), len(p.VulnCVEs()), p.DisplayName)
	}
	fmt.Printf("\n%d archetype(s). Use `list-archetypes <name>` for detail.\n", len(all))
	return nil
}

func printArchetypeDetail(p *archetype.Profile) {
	fmt.Printf("%s  —  %s\n", p.Name, p.DisplayName)
	line := func(k, v string) {
		if v != "" {
			fmt.Printf("  %-16s %s\n", k+":", v)
		}
	}
	line("family", p.Family)
	line("ssh", p.SSHBanner())
	line("http server", p.HTTPServer())
	line("http title", p.HTTPTitle())
	line("ftp", p.FTPBanner())
	line("telnet", p.TelnetBanner())
	line("smtp", p.SMTPHost())
	line("mysql", p.MySQLVersion())
	line("snmp sysDescr", p.SNMPSysDescr())
	line("snmp sysObjectID", p.SNMPSysObjectID())
	if ttl := p.ICMPTTL(); ttl > 0 {
		line("icmp ttl", fmt.Sprintf("%d", ttl))
	}
	line("patch level", p.PatchLevel())
	if cves := p.VulnCVEs(); len(cves) > 0 {
		fmt.Printf("  %-16s\n", "cve advisories:")
		for _, c := range cves {
			fmt.Printf("    %s\n", c)
		}
	}
	if svcs := p.DefaultServices(); len(svcs) > 0 {
		fmt.Printf("  %-16s\n", "default services:")
		for _, s := range svcs {
			note := ""
			if s.Note != "" {
				note = "  # " + s.Note
			}
			fmt.Printf("    :%-6d %s%s\n", s.Port, s.Handler, note)
		}
	}
}

type archetypeSummary struct {
	Name        string `json:"name"`
	DisplayName string `json:"display_name"`
	Family      string `json:"family"`
	Services    int    `json:"services"`
	CVEs        int    `json:"cves"`
}

type archetypeServiceView struct {
	Port    int    `json:"port"`
	Handler string `json:"handler"`
	Note    string `json:"note,omitempty"`
}

type archetypeDetailView struct {
	Name            string                 `json:"name"`
	DisplayName     string                 `json:"display_name"`
	Family          string                 `json:"family"`
	SSHBanner       string                 `json:"ssh_banner,omitempty"`
	HTTPServer      string                 `json:"http_server,omitempty"`
	SNMPSysDescr    string                 `json:"snmp_sys_descr,omitempty"`
	SNMPSysObjectID string                 `json:"snmp_sys_object_id,omitempty"`
	ICMPTTL         int                    `json:"icmp_ttl,omitempty"`
	PatchLevel      string                 `json:"patch_level,omitempty"`
	CVEs            []string               `json:"cves,omitempty"`
	Services        []archetypeServiceView `json:"default_services,omitempty"`
}

func archetypeView(p *archetype.Profile) archetypeDetailView {
	v := archetypeDetailView{
		Name: p.Name, DisplayName: p.DisplayName, Family: p.Family,
		SSHBanner: p.SSHBanner(), HTTPServer: p.HTTPServer(),
		SNMPSysDescr: p.SNMPSysDescr(), SNMPSysObjectID: p.SNMPSysObjectID(),
		ICMPTTL: p.ICMPTTL(), PatchLevel: p.PatchLevel(), CVEs: p.VulnCVEs(),
	}
	for _, s := range p.DefaultServices() {
		v.Services = append(v.Services, archetypeServiceView{Port: s.Port, Handler: s.Handler, Note: s.Note})
	}
	return v
}

func writeJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}
