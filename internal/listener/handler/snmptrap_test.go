package handler

import (
	"bytes"
	"context"
	"net"
	"testing"

	"github.com/rom/tarpit-honeypot/internal/config"
)

// --- tiny BER builders for crafting SNMP test packets --------------------

func snmpTLV(tag byte, content []byte) []byte {
	out := []byte{tag}
	if len(content) < 128 {
		out = append(out, byte(len(content)))
	} else {
		out = append(out, 0x82, byte(len(content)>>8), byte(len(content)))
	}
	return append(out, content...)
}
func catB(parts ...[]byte) []byte {
	var o []byte
	for _, p := range parts {
		o = append(o, p...)
	}
	return o
}
func intB(v int) []byte    { return snmpTLV(0x02, []byte{byte(v)}) }
func octB(s string) []byte { return snmpTLV(0x04, []byte(s)) }
func oidB(b []byte) []byte { return snmpTLV(0x06, b) }
func seqB(p ...[]byte) []byte {
	return snmpTLV(0x30, catB(p...))
}

var (
	oidSysUpTime = []byte{0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x03, 0x00} // 1.3.6.1.2.1.1.3.0
	oidCiscoEnt  = []byte{0x2b, 0x06, 0x01, 0x04, 0x01, 0x09}             // 1.3.6.1.4.1.9
)

func v2cTrap(community string, pduTag byte, varbinds []byte) []byte {
	pdu := snmpTLV(pduTag, catB(intB(0x10), intB(0), intB(0), varbinds))
	return seqB(intB(1), octB(community), pdu)
}

func TestInspectSNMP_V2cTrap(t *testing.T) {
	vb := seqB(seqB(oidB(oidSysUpTime), intB(0)))
	in := inspectSNMP(v2cTrap("public", pduV2Trap, vb))
	if in.Version != 1 || !in.IsTrap || in.Community != "public" {
		t.Fatalf("v2c trap parse: version=%d isTrap=%v community=%q", in.Version, in.IsTrap, in.Community)
	}
	if in.VarbindCount != 1 {
		t.Errorf("varbinds=%d; want 1", in.VarbindCount)
	}
	if len(in.Anomalies) != 0 {
		t.Errorf("clean trap flagged anomalies: %v", in.Anomalies)
	}
}

func TestInspectSNMP_V1Trap(t *testing.T) {
	pdu := snmpTLV(pduV1Trap, catB(
		oidB(oidCiscoEnt),
		snmpTLV(0x40, []byte{10, 0, 0, 1}), // agent-addr
		intB(6),                            // generic = enterpriseSpecific
		intB(1),                            // specific
		snmpTLV(0x43, []byte{0x00}),        // timestamp
		seqB(),                             // empty varbind list
	))
	in := inspectSNMP(seqB(intB(0), octB("public"), pdu))
	if in.Version != 0 || !in.IsTrap {
		t.Fatalf("v1 trap: version=%d isTrap=%v", in.Version, in.IsTrap)
	}
	if in.EnterpriseOID != "1.3.6.1.4.1.9" {
		t.Errorf("enterprise OID = %q; want 1.3.6.1.4.1.9", in.EnterpriseOID)
	}
	if in.GenericTrap != 6 || in.SpecificTrap != 1 {
		t.Errorf("trap numbers generic=%d specific=%d; want 6/1", in.GenericTrap, in.SpecificTrap)
	}
}

func TestInspectSNMP_Anomalies(t *testing.T) {
	// Malformed: not a SEQUENCE.
	if a := inspectSNMP([]byte{0xde, 0xad, 0xbe, 0xef}).Anomalies; !contains(a, "snmp-malformed-asn1") {
		t.Errorf("malformed not flagged: %v", a)
	}
	// Non-standard version (7).
	pdu := snmpTLV(pduV2Trap, catB(intB(1), intB(0), intB(0), seqB()))
	if a := inspectSNMP(seqB(intB(7), octB("x"), pdu)).Anomalies; !contains(a, "snmp-nonstandard-version") {
		t.Errorf("nonstandard version not flagged: %v", a)
	}
	// Oversized OID (40 arcs) in a varbind → overflow + Cisco SNMP RCE CVEs.
	bigOID := append([]byte{0x2b}, bytes.Repeat([]byte{0x01}, 38)...) // 2 + 38 = 40 arcs
	vb := seqB(seqB(oidB(bigOID), intB(0)))
	in := inspectSNMP(v2cTrap("public", pduV2Trap, vb))
	if !contains(in.Anomalies, "snmp-oversized-oid") {
		t.Fatalf("oversized OID not flagged: %v", in.Anomalies)
	}
	if !contains(in.CVEs, "CVE-2017-6736") || !contains(in.CVEs, "CVE-2025-20352") {
		t.Errorf("Cisco SNMP RCE CVEs not attributed: %v", in.CVEs)
	}
}

func TestSNMPTrapHandler_InformAck(t *testing.T) {
	vb := seqB(seqB(oidB(oidSysUpTime), intB(0)))
	pkt := v2cTrap("public", pduInform, vb)
	pc := &capPC{}
	h := &snmptrap{}
	res, err := h.Handle(context.Background(), pkt, &net.UDPAddr{IP: net.ParseIP("203.0.113.5"), Port: 4000}, pc, config.Listener{})
	if err != nil {
		t.Fatal(err)
	}
	if res.Meta["snmp_pdu"] != "inform" {
		t.Errorf("snmp_pdu = %v; want inform", res.Meta["snmp_pdu"])
	}
	if len(pc.wrote) == 0 {
		t.Fatal("no inform acknowledgement written")
	}
	// The ack is the request with the PDU tag flipped InformRequest -> Response.
	idx := bytes.IndexByte(pkt, pduInform)
	if idx < 0 || pc.wrote[idx] != pduGetResponse {
		t.Errorf("ack PDU tag not flipped to GetResponse at %d: % x", idx, pc.wrote)
	}
}

func TestSNMPTrapHandler_MalformedNoPanic(t *testing.T) {
	pc := &capPC{}
	h := &snmptrap{}
	// Garbage + an empty packet must not panic and must flag malformed.
	for _, p := range [][]byte{{0x00}, {}, {0x30, 0x84, 0xff, 0xff, 0xff, 0xff}} {
		res, err := h.Handle(context.Background(), p, &net.UDPAddr{}, pc, config.Listener{})
		if err != nil {
			t.Fatalf("Handle(% x) err: %v", p, err)
		}
		if res.Meta["snmp_pdu"] == nil {
			t.Errorf("Handle(% x) left snmp_pdu unset", p)
		}
	}
}
