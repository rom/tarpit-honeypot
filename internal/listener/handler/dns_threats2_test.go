package handler

import "testing"

func TestDNSThreatSecondPass(t *testing.T) {
	markersFor := func(qname string, qtype uint16) map[string]bool {
		msg := buildDNSQuery(qname, qtype)
		q, ok := parseDNSQuery(msg)
		if !ok {
			t.Fatalf("parseDNSQuery failed for %q", qname)
		}
		set := map[string]bool{}
		for _, m := range dnsThreatMarkers(msg, q) {
			set[m] = true
		}
		return set
	}

	if m := markersFor("MyHost.Example.Com", 1); !m["dns-0x20-encoding"] {
		t.Errorf("mixed-case not flagged: %v", m)
	}
	if m := markersFor("10-0-0-1.attacker.com", 1); !m["dns-embedded-ip-rebind"] {
		t.Errorf("embedded-IP rebind not flagged: %v", m)
	}
	if m := markersFor("example.com", 48); !m["dns-largeset-amplification"] { // DNSKEY
		t.Errorf("DNSKEY large-RRset amplification not flagged: %v", m)
	}
	if m := markersFor("example.com", 16); !m["dns-largeset-amplification"] { // TXT
		t.Errorf("TXT large-RRset amplification not flagged: %v", m)
	}
	// A lowercase ordinary A query should NOT trip the mixed-case marker.
	if m := markersFor("plain.example.com", 1); m["dns-0x20-encoding"] {
		t.Errorf("lowercase query wrongly flagged 0x20: %v", m)
	}
}

func TestDNSTSIGBadClass(t *testing.T) {
	// Construct a message containing an hmac- algorithm name and a TYPE-250 RR
	// whose class != ANY(0x00ff).
	msg := []byte{0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}
	msg = append(msg, 0x00, 0x00, 0xfa, 0x00, 0x01) // root, TYPE 250, CLASS IN (bad for TSIG)
	msg = append(msg, []byte("hmac-sha256")...)
	if !dnsHasTSIG(msg) {
		t.Fatal("dnsHasTSIG should detect the hmac- algorithm name")
	}
	if !dnsTSIGBadClass(msg) {
		t.Error("TSIG with class IN should be flagged as bad-class (CVE-2025-40775)")
	}
}
