package handler

import (
	"testing"

	"github.com/rom/tarpit-honeypot/internal/config"
)

func TestSetTLSDefaults(t *testing.T) {
	SetTLSDefaults("", "")
	if got := defaultCertHost(); got != "localhost" {
		t.Errorf("defaultCertHost() = %q; want localhost", got)
	}
	SetTLSDefaults("  honeypot.corp.example  ", "Contoso Ltd")
	if got := defaultCertHost(); got != "honeypot.corp.example" {
		t.Errorf("defaultCertHost() = %q; want honeypot.corp.example", got)
	}
	if defaultTLSOrg != "Contoso Ltd" {
		t.Errorf("defaultTLSOrg = %q; want Contoso Ltd", defaultTLSOrg)
	}
	if hs := tlsHosts(config.Listener{}); len(hs) != 1 || hs[0] != "honeypot.corp.example" {
		t.Errorf("tlsHosts default = %v; want [honeypot.corp.example]", hs)
	}
	SetTLSDefaults("", "")
}
