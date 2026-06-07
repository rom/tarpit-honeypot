package identity

import (
	"strings"
	"testing"
)

func TestHostNameUsesDomain(t *testing.T) {
	id := New("seed-xyz")
	if got := id.Domain(); got != "example.internal" {
		t.Errorf("default Domain() = %q; want example.internal", got)
	}
	if !strings.HasSuffix(id.HostName(), ".example.internal") {
		t.Errorf("default HostName() = %q; want .example.internal suffix", id.HostName())
	}
	id.SetDomain("corp.acme.test")
	if id.Domain() != "corp.acme.test" {
		t.Errorf("Domain() after SetDomain = %q", id.Domain())
	}
	if !strings.HasSuffix(id.HostName(), ".corp.acme.test") {
		t.Errorf("HostName() = %q; want .corp.acme.test suffix", id.HostName())
	}
	// Leading dot trimmed.
	id.SetDomain(".lab.example")
	if id.Domain() != "lab.example" {
		t.Errorf("leading dot not trimmed: %q", id.Domain())
	}
}

func TestDerivePropagatesDomain(t *testing.T) {
	id := New("seed-1")
	id.SetDomain("corp.example.com")
	child := id.Derive("host/10.0.0.5")
	if child.Domain() != "corp.example.com" {
		t.Errorf("derived identity domain = %q; want corp.example.com", child.Domain())
	}
	if got := child.HostName(); !contains(got, ".corp.example.com") {
		t.Errorf("derived HostName() = %q; want .corp.example.com suffix", got)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
