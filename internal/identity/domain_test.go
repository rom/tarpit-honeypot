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
