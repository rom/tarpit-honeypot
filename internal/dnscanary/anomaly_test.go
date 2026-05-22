package dnscanary

import (
	"strings"
	"testing"
)

func has(list []string, s string) bool {
	for _, e := range list {
		if e == s {
			return true
		}
	}
	return false
}

func TestDNSAnomalies(t *testing.T) {
	// Normal lookup -> no anomalies.
	if a := dnsAnomalies("www.example.com", 1, 40); len(a) != 0 {
		t.Errorf("normal query flagged: %v", a)
	}

	// Tunneling: a long high-entropy label.
	tunnelLabel := "k7f9d2a1b8c3e5f60718293a4b5c6d7e8f90a1b2"
	if a := dnsAnomalies(tunnelLabel+".tunnel.evil.com", 16, 80); !has(a, "dns-high-entropy-label") {
		t.Errorf("high-entropy label not flagged: %v", a)
	}

	// TXT qtype is tunneling-favored.
	if a := dnsAnomalies("data.evil.com", 16, 40); !has(a, "dns-tunneling-qtype") {
		t.Errorf("TXT qtype not flagged: %v", a)
	}
	// NULL qtype too.
	if a := dnsAnomalies("data.evil.com", 10, 40); !has(a, "dns-tunneling-qtype") {
		t.Errorf("NULL qtype not flagged: %v", a)
	}

	// Over-long qname.
	long := strings.Repeat("ab.", 80) + "evil.com"
	if a := dnsAnomalies(long, 1, 300); !has(a, "dns-qname-overlong") {
		t.Errorf("overlong qname not flagged: %v", a)
	}

	// Oversize query message.
	if a := dnsAnomalies("x.com", 1, 600); !has(a, "dns-oversize-query") {
		t.Errorf("oversize query not flagged: %v", a)
	}

	// DNSCrypt certificate lookup.
	if a := dnsAnomalies("2.dnscrypt-cert.example.com", 16, 60); !has(a, "dnscrypt-probe") {
		t.Errorf("dnscrypt-cert query not flagged: %v", a)
	}

	// DGA: a vowel-poor random A-record SLD is flagged...
	if a := dnsAnomalies("kjqwxzbmwptr.com", 1, 40); !has(a, "dns-dga-suspected") {
		t.Errorf("DGA-shaped A query not flagged: %v", a)
	}
	// ...but common domains are not, and DGA only applies to A/AAAA.
	for _, n := range []string{"www.google.com", "mail.example.org", "api.github.com"} {
		if a := dnsAnomalies(n, 1, 40); has(a, "dns-dga-suspected") {
			t.Errorf("legit domain %q false-flagged as DGA: %v", n, a)
		}
	}
}

func TestLooksDGALabel(t *testing.T) {
	for _, dga := range []string{"kjqwxzbmwptr", "x7y2q9z4w1k8", "bcdfghjklmnp"} {
		if !looksDGALabel(dga) {
			t.Errorf("%q should look DGA", dga)
		}
	}
	for _, ok := range []string{"google", "example", "administration", "cloudfront", "short"} {
		if looksDGALabel(ok) {
			t.Errorf("%q should NOT look DGA", ok)
		}
	}
}

func TestLooksEncodedLabel(t *testing.T) {
	// English-ish label: not flagged.
	if looksEncodedLabel("administration") {
		t.Errorf("dictionary-ish label false positive")
	}
	// Base32/hex chunk: flagged.
	if !looksEncodedLabel("a1b2c3d4e5f60718293a4b5c") {
		t.Errorf("encoded chunk not detected")
	}
	// Contains a separator -> not a single chunk.
	if looksEncodedLabel("ab-cd-ef-12-34-56-78-90") {
		t.Errorf("hyphenated string should not count as single encoded chunk")
	}
}
