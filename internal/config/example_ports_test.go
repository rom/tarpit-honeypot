package config

import (
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// realisticExampleConfigs are the shipped configs that model a real host, so
// their listeners should bind services to their real ports with the right
// handler. The harness-* and example-FULL/LARGE configs intentionally pack every
// handler onto arbitrary non-privileged ports, so they are excluded.
func realisticExampleConfigs(t *testing.T) []string {
	t.Helper()
	var out []string
	for _, pat := range []string{"../../configs/tarpit-honeypot.example-*.yaml", "../../examples/*.yaml"} {
		m, err := filepath.Glob(pat)
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range m {
			b := filepath.Base(f)
			if strings.Contains(b, "example-FULL") || strings.Contains(b, "example-LARGE") {
				continue
			}
			out = append(out, f)
		}
	}
	if len(out) == 0 {
		t.Fatal("no example configs found")
	}
	return out
}

func portOf(bind string) int {
	i := strings.LastIndex(bind, ":")
	if i < 0 {
		return 0
	}
	p, _ := strconv.Atoi(bind[i+1:])
	return p
}

// TestExampleConfigsUseRealPortsForTLSServices guards against the class of bug
// where a well-known TLS / protocol port is served by the wrong handler (e.g.
// the plain `https` handler on 636/LDAPS, which answers an LDAP-over-TLS probe
// with HTTP — an obvious honeypot tell). Each canonical port maps to the handler
// family that may serve it.
func TestExampleConfigsUseRealPortsForTLSServices(t *testing.T) {
	allowed := map[int]map[string]bool{
		636:   {"ldaps": true},                       // LDAPS, not https
		993:   {"imaps": true},                       // IMAPS, not https
		995:   {"pop3s": true},                       // POP3S, not https
		465:   {"smtps": true},                       // SMTPS, not https
		990:   {"ftps": true},                        // FTPS control, not https
		389:   {"ldap": true},                        // LDAP, not http
		3268:  {"ldap": true},                        // AD Global Catalog
		3269:  {"ldaps": true},                       // AD Global Catalog over TLS
		3389:  {"rdp": true, "rdp_udp": true},        // RDP
		1433:  {"mssql": true},                       // MS SQL
		3306:  {"mysql": true},                       // MySQL
		5432:  {"postgres": true},                    // PostgreSQL
		6379:  {"redis": true, "scripted": true},     // Redis
		11211: {"memcached": true, "scripted": true}, // memcached
	}
	for _, f := range realisticExampleConfigs(t) {
		cfg, err := Load(f)
		if err != nil {
			t.Errorf("%s: load: %v", filepath.Base(f), err)
			continue
		}
		for _, l := range cfg.Listeners {
			fam, ok := allowed[portOf(l.Bind)]
			if !ok {
				continue
			}
			if !fam[l.Handler] {
				t.Errorf("%s: listener %q binds port %d with handler %q; that port expects one of %v",
					filepath.Base(f), l.ID, portOf(l.Bind), l.Handler, keysOf(fam))
			}
		}
	}
}

func keysOf(m map[string]bool) []string {
	var ks []string
	for k := range m {
		ks = append(ks, k)
	}
	return ks
}
