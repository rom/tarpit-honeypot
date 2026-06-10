package handler

import (
	"context"
	"net"
	"testing"

	g "github.com/gosnmp/gosnmp"

	"github.com/rom/tarpit-honeypot/internal/config"
)

// snmpSetPacket marshals a v2c SetRequest for the given OID + string value.
func snmpSetPacket(t *testing.T, community, oid, val string) []byte {
	t.Helper()
	p := &g.GoSNMP{Version: g.Version2c, Community: community}
	pkt := &g.SnmpPacket{
		Version: g.Version2c, Community: community, PDUType: g.SetRequest, RequestID: 1,
		Variables: []g.SnmpPDU{{Name: oid, Type: g.OctetString, Value: []byte(val)}},
	}
	_ = p
	out, err := pkt.MarshalMsg()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return out
}

func TestSNMPSetExtendExec(t *testing.T) {
	pkt := snmpSetPacket(t, "private", ".1.3.6.1.4.1.8072.1.3.2.2.1.2.3.102.111.111", "/bin/sh")
	res, _ := (&snmp{}).Handle(context.Background(), pkt, &net.UDPAddr{IP: net.IPv4(203, 0, 113, 1)}, &fakePacketConn{}, config.Listener{})
	if !hasAnom(res, "snmp-extend-exec") || !hasAnom(res, "cve:CVE-2020-15862") {
		t.Errorf("EXTEND-MIB exec not flagged: %v", res.Meta["anomalies"])
	}
}

func TestSNMPExpandedCommunity(t *testing.T) {
	pkt := snmpSetPacket(t, "cisco", ".1.3.6.1.2.1.1.5.0", "x")
	res, _ := (&snmp{}).Handle(context.Background(), pkt, &net.UDPAddr{IP: net.IPv4(203, 0, 113, 1)}, &fakePacketConn{}, config.Listener{})
	if res.Meta["snmp_default_community"] != true {
		t.Errorf("'cisco' community not flagged as default/guessed: %v", res.Meta)
	}
	if !hasAnom(res, "snmp-identity-rewrite") {
		t.Errorf("sysName rewrite not flagged: %v", res.Meta["anomalies"])
	}
}
