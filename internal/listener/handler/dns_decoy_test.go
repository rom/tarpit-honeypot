package handler

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/identity"
)

// dnsQ builds a single-question DNS message with an explicit qtype + qclass.
func dnsQ(name string, qtype, qclass uint16) []byte {
	msg := make([]byte, 12)
	binary.BigEndian.PutUint16(msg[4:6], 1) // QDCOUNT
	for _, l := range bytes.Split([]byte(name), []byte(".")) {
		if len(l) == 0 {
			continue
		}
		msg = append(msg, byte(len(l)))
		msg = append(msg, l...)
	}
	msg = append(msg, 0)
	msg = binary.BigEndian.AppendUint16(msg, qtype)
	msg = binary.BigEndian.AppendUint16(msg, qclass)
	return msg
}

func TestDNSVersionBind(t *testing.T) {
	d := &dnsHandler{id: identity.New("seed-vb")}
	// CHAOS (3) TXT (16) version.bind with an operator-set vulnerable banner.
	msg := dnsQ("version.bind", 16, 3)
	q, ok := parseDNSQuery(msg)
	if !ok || q.qclass != 3 {
		t.Fatalf("parse: ok=%v qclass=%d", ok, q.qclass)
	}
	cfg := config.Listener{DNS: config.DNSResponder{VersionBind: "9.8.1-P1-vuln"}}
	resp := d.buildAnswer(msg, q, cfg)
	if !bytes.Contains(resp, []byte("9.8.1-P1-vuln")) {
		t.Errorf("version.bind reply missing configured banner: %q", resp)
	}
	// Default (no override) still answers with a decoy version.
	resp2 := d.buildAnswer(msg, q, config.Listener{})
	if !bytes.Contains(resp2, []byte("9.8.1")) {
		t.Errorf("default version.bind reply missing decoy: %q", resp2)
	}
}

func TestDNSFakeZoneAXFR(t *testing.T) {
	d := &dnsHandler{id: identity.New("seed-zone")}
	msg := dnsQ("corp.example", 252, 1) // AXFR, IN
	q, _ := parseDNSQuery(msg)
	cfg := config.Listener{DNS: config.DNSResponder{FakeZone: true, ExtraTXT: []string{"leaked-api-key=ABC123"}}}
	msgs := d.buildFakeZone(msg, q, cfg)
	if len(msgs) == 0 {
		t.Fatal("no zone-transfer message produced")
	}
	blob := msgs[0]
	for _, want := range []string{"vault", "jenkins", "_ldap", "leaked-api-key=ABC123"} {
		if !bytes.Contains(blob, []byte(want)) {
			t.Errorf("fake zone missing %q", want)
		}
	}
	// AXFR must open and close with an SOA → ANCOUNT well above a single record.
	if an := binary.BigEndian.Uint16(blob[6:8]); an < 20 {
		t.Errorf("fake zone ANCOUNT = %d, want a populated zone", an)
	}
}

func TestDNSZoneTransferDetected(t *testing.T) {
	got := dnsQueryAnomalies("corp.example", 252, 40)
	if !containsStr(got, "dns-zone-transfer") {
		t.Errorf("AXFR not flagged: %v", got)
	}
}
