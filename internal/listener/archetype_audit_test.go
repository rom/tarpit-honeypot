package listener

import (
	"fmt"
	"sort"
	"testing"

	"github.com/rom/tarpit-honeypot/internal/archetype"
	"github.com/rom/tarpit-honeypot/internal/listener/handler"
)

// handlerExists reports whether name resolves to a registered TCP or UDP
// handler. Deps{} is fine: constructors only error on an unknown name.
func handlerExists(name string) bool {
	if _, err := handler.Get(name, handler.Deps{}); err == nil {
		return true
	}
	if _, err := handler.GetUDP(name, handler.Deps{}); err == nil {
		return true
	}
	return false
}

// TestArchetypeServicesResolve audits every archetype's defaultServices: each
// must name a registered handler, sit on a valid port, and not collide with
// another service in the same archetype. Reports all faults; fails if any.
func TestArchetypeServicesResolve(t *testing.T) {
	var faults []string
	unknownHandlers := map[string]int{}

	for _, p := range archetype.All() {
		seen := map[int]string{}
		for _, s := range p.DefaultServices() {
			if s.Port < 1 || s.Port > 65535 {
				faults = append(faults, fmt.Sprintf("%s: invalid port %d (handler %q)", p.Name, s.Port, s.Handler))
			}
			if prev, dup := seen[s.Port]; dup {
				faults = append(faults, fmt.Sprintf("%s: duplicate port %d (%q and %q)", p.Name, s.Port, prev, s.Handler))
			} else {
				seen[s.Port] = s.Handler
			}
			if s.Handler == "" {
				faults = append(faults, fmt.Sprintf("%s: empty handler on port %d", p.Name, s.Port))
				continue
			}
			if !handlerExists(s.Handler) {
				faults = append(faults, fmt.Sprintf("%s: port %d -> unknown handler %q", p.Name, s.Port, s.Handler))
				unknownHandlers[s.Handler]++
			}
		}
	}

	if len(unknownHandlers) > 0 {
		keys := make([]string, 0, len(unknownHandlers))
		for k := range unknownHandlers {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			t.Logf("unknown handler %q referenced by %d archetype service(s)", k, unknownHandlers[k])
		}
	}
	sort.Strings(faults)
	for _, f := range faults {
		t.Errorf("%s", f)
	}
	if len(faults) == 0 {
		t.Logf("audited %d archetypes — all defaultServices resolve to a known handler", len(archetype.All()))
	}
}

// TestArchetypeFingerprintCoherence is informational (logs, never fails): it
// surfaces archetypes that declare a service but carry no matching identity
// banner (the handler then falls back to the generic identity pool, which is
// fine but less coherent). Run with -v to see the report.
func TestArchetypeFingerprintCoherence(t *testing.T) {
	type gap struct{ name, svc, missing string }
	var gaps []gap
	for _, p := range archetype.All() {
		has := map[string]bool{}
		for _, s := range p.DefaultServices() {
			has[s.Handler] = true
		}
		if (has["ssh"] || has["ssh_interactive"]) && p.SSHBanner() == "" {
			gaps = append(gaps, gap{p.Name, "ssh", "sshBanner"})
		}
		if (has["http"] || has["https"]) && p.HTTPServer() == "" && p.HTTPTitle() == "" {
			gaps = append(gaps, gap{p.Name, "http", "httpServer/httpTitle"})
		}
		if has["snmp"] && p.SNMPSysDescr() == "" {
			gaps = append(gaps, gap{p.Name, "snmp", "snmpSysDescr"})
		}
		// FTP falls back to a default banner when ftpFeatures are set; telnet
		// uses loginPrompt when telnetBanner is empty — so only flag when BOTH
		// the banner and its fallback are absent.
		if has["ftp"] && p.FTPBanner() == "" && len(p.FTPFeatures()) == 0 {
			gaps = append(gaps, gap{p.Name, "ftp", "ftpBanner/ftpFeatures"})
		}
		if has["telnet"] && p.TelnetBanner() == "" && p.LoginPrompt() == "" {
			gaps = append(gaps, gap{p.Name, "telnet", "telnetBanner/loginPrompt"})
		}
	}
	sort.Slice(gaps, func(i, j int) bool {
		if gaps[i].missing != gaps[j].missing {
			return gaps[i].missing < gaps[j].missing
		}
		return gaps[i].name < gaps[j].name
	})
	t.Logf("fingerprint coherence: %d service/identity gaps (informational; handler falls back to identity pool)", len(gaps))
	for _, g := range gaps {
		t.Logf("  %-28s declares %-7s but no %s", g.name, g.svc, g.missing)
	}
}
