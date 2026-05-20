package handler

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"testing"

	"github.com/rom/tarpit-honeypot/internal/config"
)

func adTopo() HoneynetSnapshot {
	return HoneynetSnapshot{
		Networks: []HoneynetNetwork{{ID: "corp", CIDR: "10.99.0.0/24", Domain: "corp.example.local", DNS: "10.99.0.2"}},
		Hosts: []HoneynetHost{
			{NetID: "corp", IP: "10.99.0.20", Hostname: "dc01", OS: "windows", Services: []HoneynetService{{Port: 389, Handler: "ldap"}, {Port: 88, Handler: "kerberos"}}},
			{NetID: "corp", IP: "10.99.0.10", Hostname: "web01", OS: "linux", Services: []HoneynetService{{Port: 80, Handler: "http"}}},
			{NetID: "corp", IP: "10.99.0.25", Hostname: "mail01", OS: "linux", Services: []HoneynetService{{Port: 25, Handler: "smtp_recv"}}},
		},
	}
}

// firstAnswer returns the rrtype + rdata of the first answer RR. The
// query (header + one question, no answers) ends exactly where the
// answer section begins in the response.
func firstAnswer(t *testing.T, query, resp []byte) (uint16, []byte) {
	t.Helper()
	off := len(query)
	if off+12 > len(resp) {
		t.Fatalf("response too short for an answer: %d", len(resp))
	}
	rrtype := binary.BigEndian.Uint16(resp[off+2 : off+4])
	rdlen := int(binary.BigEndian.Uint16(resp[off+10 : off+12]))
	if off+12+rdlen > len(resp) {
		t.Fatalf("rdata out of bounds")
	}
	return rrtype, resp[off+12 : off+12+rdlen]
}

func resolve(t *testing.T, d *dnsHandler, name string, qtype uint16) (query []byte, rrtype uint16, rdata []byte, ancount uint16) {
	t.Helper()
	pc := &fakePacketConn{}
	src := &net.UDPAddr{IP: net.IPv4(10, 1, 1, 1), Port: 5300}
	query = buildDNSQuery(name, qtype)
	if _, err := d.Handle(context.Background(), query, src, pc, config.Listener{}); err != nil {
		t.Fatal(err)
	}
	if len(pc.written) != 1 {
		t.Fatalf("expected 1 reply; got %d", len(pc.written))
	}
	resp := pc.written[0]
	ancount = dnsAnswerCount(resp)
	if ancount > 0 {
		rrtype, rdata = firstAnswer(t, query, resp)
	}
	return query, rrtype, rdata, ancount
}

func TestDNSResolvesHoneynetHostA(t *testing.T) {
	d := &dnsHandler{topo: adTopo()}
	_, _, rdata, an := resolve(t, d, "dc01.corp.example.local", 1)
	if an != 1 || len(rdata) != 4 {
		t.Fatalf("A: ancount=%d rdata=%v", an, rdata)
	}
	if got := net.IP(rdata).String(); got != "10.99.0.20" {
		t.Errorf("dc01 A = %s; want the virtual host IP 10.99.0.20", got)
	}
	// Bare hostname (no domain) also resolves.
	if _, _, rd, _ := resolve(t, d, "web01", 1); net.IP(rd).String() != "10.99.0.10" {
		t.Errorf("web01 A = %s; want 10.99.0.10", net.IP(rd))
	}
}

func TestDNSPTRResolvesHoneynetHost(t *testing.T) {
	d := &dnsHandler{topo: adTopo()}
	_, rrtype, rdata, an := resolve(t, d, "20.0.99.10.in-addr.arpa", 12)
	if an != 1 || rrtype != 12 {
		t.Fatalf("PTR ancount=%d rrtype=%d", an, rrtype)
	}
	if !bytes.Contains(rdata, []byte("dc01")) {
		t.Errorf("PTR for 10.99.0.20 should name dc01; rdata=%q", rdata)
	}
}

func TestDNSSRVResolvesAD(t *testing.T) {
	d := &dnsHandler{topo: adTopo()}
	for _, tc := range []struct {
		name string
		port uint16
	}{
		{"_ldap._tcp.corp.example.local", 389},
		{"_kerberos._udp.corp.example.local", 88},
		{"_ldap._tcp.dc._msdcs.corp.example.local", 389}, // AD _msdcs form
	} {
		_, rrtype, rdata, an := resolve(t, d, tc.name, 33)
		if an != 1 || rrtype != 33 {
			t.Fatalf("%s: ancount=%d rrtype=%d", tc.name, an, rrtype)
		}
		port := binary.BigEndian.Uint16(rdata[4:6])
		if port != tc.port {
			t.Errorf("%s: SRV port = %d; want %d", tc.name, port, tc.port)
		}
		if !bytes.Contains(rdata, []byte("dc01")) {
			t.Errorf("%s: SRV target should be dc01; rdata=%q", tc.name, rdata)
		}
	}
}

func TestDNSHINFOFromArchetype(t *testing.T) {
	d := &dnsHandler{topo: adTopo()}
	_, rrtype, rdata, an := resolve(t, d, "dc01.corp.example.local", 13)
	if an != 1 || rrtype != 13 {
		t.Fatalf("HINFO ancount=%d rrtype=%d", an, rrtype)
	}
	if !bytes.Contains(rdata, []byte("Windows")) {
		t.Errorf("HINFO for the windows DC should mention Windows; rdata=%q", rdata)
	}
}

func TestDNSMXAndNSCoherent(t *testing.T) {
	d := &dnsHandler{topo: adTopo()}
	// MX should point at the host running smtp_recv.
	if _, _, rdata, an := resolve(t, d, "corp.example.local", 15); an != 1 || !bytes.Contains(rdata, []byte("mail01")) {
		t.Errorf("MX should target mail01; ancount=%d rdata=%q", an, rdata)
	}
	// SOA answered for the domain.
	if _, rrtype, _, an := resolve(t, d, "corp.example.local", 6); an != 1 || rrtype != 6 {
		t.Errorf("SOA: ancount=%d rrtype=%d", an, rrtype)
	}
	// LOC answered.
	if _, rrtype, rdata, an := resolve(t, d, "dc01.corp.example.local", 29); an != 1 || rrtype != 29 || len(rdata) != 16 {
		t.Errorf("LOC: ancount=%d rrtype=%d len=%d", an, rrtype, len(rdata))
	}
}

func TestDNSUnknownNameStillFabricates(t *testing.T) {
	d := &dnsHandler{topo: adTopo()}
	// A name outside the topology falls back to a fabricated public A.
	_, _, rdata, an := resolve(t, d, "random.example.org", 1)
	if an != 1 || len(rdata) != 4 {
		t.Fatalf("fabricated A: ancount=%d rdata=%v", an, rdata)
	}
	if rdata[0] == 10 || rdata[0] == 192 || rdata[0] == 127 {
		t.Errorf("fabricated A in reserved space: %v", net.IP(rdata))
	}
}
