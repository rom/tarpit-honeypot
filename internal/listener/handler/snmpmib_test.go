package handler

import (
	"context"
	"net"
	"strings"
	"testing"

	g "github.com/gosnmp/gosnmp"

	"github.com/rom/tarpit-honeypot/internal/archetype"
	"github.com/rom/tarpit-honeypot/internal/config"
)

func testSNMPArch(t *testing.T) *archetype.Profile {
	t.Helper()
	p := archetype.Lookup("moxa-eds-405a")
	if p == nil {
		t.Fatal("archetype moxa-eds-405a not found")
	}
	return p
}

func testHosts() []HoneynetHost {
	return []HoneynetHost{
		{IP: "10.0.0.5", MAC: "aa:bb:cc:dd:ee:05", Hostname: "plc5", OS: "vxworks"},
		{IP: "10.0.0.6", MAC: "aa:bb:cc:dd:ee:06", Hostname: "hmi6", OS: "windows"},
	}
}

// walk drives mibNext from a base OID like a real snmpwalk and returns the
// ordered list of returned OIDs (string form).
func walk(mib []mibEntry, base string) []string {
	var out []string
	cur := base
	for i := 0; i < 1000; i++ {
		pdu := mibNextVarbind(mib, cur)
		if pdu.Type == g.Null {
			break
		}
		name := strings.TrimPrefix(pdu.Name, ".")
		out = append(out, name)
		cur = pdu.Name
	}
	return out
}

func TestSNMPWalkIsOrderedAndComplete(t *testing.T) {
	mib := buildSNMPMIB(testSNMPArch(t), testHosts(), mibNetwork)
	got := walk(mib, "1")
	if len(got) < 20 {
		t.Fatalf("walk too short (%d) — GetNext not traversing", len(got))
	}
	// Strictly increasing OID order (the property snmpwalk relies on).
	for i := 1; i < len(got); i++ {
		a, _ := parseOID(got[i-1])
		b, _ := parseOID(got[i])
		if !oidLess(a, b) {
			t.Fatalf("walk not strictly increasing at %d: %s !< %s", i, got[i-1], got[i])
		}
	}
	has := func(o string) bool {
		for _, x := range got {
			if x == o {
				return true
			}
		}
		return false
	}
	// System group, ifTable, and the walkable topology (ARP) table.
	if !has("1.3.6.1.2.1.1.1.0") {
		t.Error("walk missing sysDescr")
	}
	if !has("1.3.6.1.2.1.2.2.1.2.1") {
		t.Error("walk missing ifDescr.1")
	}
	if !has("1.3.6.1.2.1.4.22.1.3.1.10.0.0.5") || !has("1.3.6.1.2.1.4.22.1.3.1.10.0.0.6") {
		t.Errorf("walk missing ipNetToMediaTable topology entries: %v", got)
	}
}

func TestSNMPProfilesGate(t *testing.T) {
	arch, hosts := testSNMPArch(t), testHosts()
	contains := func(mib []mibEntry, oid string) bool {
		o, _ := parseOID(oid)
		_, ok := mibGet(mib, o)
		return ok
	}
	min := buildSNMPMIB(arch, hosts, mibMinimal)
	if contains(min, "1.3.6.1.2.1.2.1.0") {
		t.Error("minimal profile must not expose ifNumber")
	}
	host := buildSNMPMIB(arch, hosts, mibHost)
	if !contains(host, "1.3.6.1.2.1.2.1.0") {
		t.Error("host profile must expose ifNumber")
	}
	if contains(host, "1.3.6.1.2.1.4.22.1.3.1.10.0.0.5") {
		t.Error("host profile must not expose the ARP/topology table")
	}
	net := buildSNMPMIB(arch, hosts, mibNetwork)
	if !contains(net, "1.3.6.1.2.1.4.22.1.3.1.10.0.0.5") {
		t.Error("network profile must expose the ARP/topology table")
	}
}

func TestSNMPGetBulk(t *testing.T) {
	mib := buildSNMPMIB(testSNMPArch(t), nil, mibHost)
	pkt := &g.SnmpPacket{
		Version: g.Version2c, PDUType: g.GetBulkRequest,
		NonRepeaters: 0, MaxRepetitions: 5,
		Variables: []g.SnmpPDU{{Name: "1.3.6.1.2.1.1", Type: g.Null}},
	}
	out := bulkResponse(mib, pkt)
	if len(out) != 5 {
		t.Fatalf("GetBulk maxRep=5 returned %d varbinds", len(out))
	}
	if strings.TrimPrefix(out[0].Name, ".") != "1.3.6.1.2.1.1.1.0" {
		t.Errorf("first bulk varbind = %s; want sysDescr", out[0].Name)
	}
}

// TestSNMPWalkRateLimitDrops drives the handler with GetNext packets and a
// rate limit of 1/min and no tarpit — the second step must be dropped.
func TestSNMPWalkRateLimitDrops(t *testing.T) {
	h := &snmp{arch: testSNMPArch(t)}
	cfg := config.Listener{SNMP: config.SNMPListener{MIBProfile: "host", WalkRatePerMin: 1}}
	mkNext := func() []byte {
		p := &g.SnmpPacket{Version: g.Version2c, Community: "public", PDUType: g.GetNextRequest, RequestID: 1,
			Variables: []g.SnmpPDU{{Name: "1.3.6.1.2.1.1.1.0", Type: g.Null}}}
		b, err := p.MarshalMsg()
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	src := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 9), Port: 4444}
	pc := &fakePacketConn{}
	// First GetNext: answered.
	if _, err := h.Handle(context.Background(), mkNext(), src, pc, cfg); err != nil {
		t.Fatal(err)
	}
	if len(pc.written) != 1 {
		t.Fatalf("first walk step should be answered; wrote %d", len(pc.written))
	}
	// Second GetNext from same source: over the 1/min cap → dropped + flagged.
	res, _ := h.Handle(context.Background(), mkNext(), src, pc, cfg)
	if len(pc.written) != 1 {
		t.Errorf("over-limit walk step should be dropped; total writes %d", len(pc.written))
	}
	anoms, _ := res.Meta["anomalies"].([]string)
	if !containsStr(anoms, "snmp-walk-rate-exceeded") {
		t.Errorf("expected snmp-walk-rate-exceeded; meta=%v", res.Meta["anomalies"])
	}
}
