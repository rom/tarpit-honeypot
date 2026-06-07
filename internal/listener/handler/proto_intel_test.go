package handler

import (
	"context"
	"net"
	"strings"
	"testing"

	g "github.com/gosnmp/gosnmp"

	"github.com/rom/tarpit-honeypot/internal/config"
)

// NTP mode-7 monlist must be flagged as amplification + CVE-2013-5211, with an
// intent label — and must NOT be answered (no reflection).
func TestNTPMonlistIntent(t *testing.T) {
	pkt := make([]byte, 48)
	pkt[0] = (2 << 3) | 7 // version 2, mode 7 (private/ntpdc)
	pkt[3] = 42           // REQ_MON_GETLIST
	pc := &fakePacketConn{}
	res, _ := (&ntp{lim: newUDPReflectLimiter()}).Handle(context.Background(), pkt, &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4)}, pc, config.Listener{})

	an := anomaliesOf(res)
	for _, want := range []string{"ntp-monlist-amplification", "cve:CVE-2013-5211"} {
		if !containsStr(an, want) {
			t.Errorf("monlist anomalies missing %q: %v", want, an)
		}
	}
	if it, _ := res.Meta["intent"].(string); !strings.Contains(it, "monlist") {
		t.Errorf("intent = %q, want a monlist label", it)
	}
	// monlist is now answered (engages ntpdc) but with exactly ONE entry — a
	// single mon_getlist_1 record (72 bytes), never the ~600-entry amplifier.
	if len(pc.written) != 1 {
		t.Fatalf("monlist should be answered with one bounded reply; got %d", len(pc.written))
	}
	if n := len(pc.written[0]); n != 8+72 {
		t.Errorf("monlist reply = %d bytes; want 80 (8 hdr + 1 entry, non-amplifying)", n)
	}
}

func TestNTPControlIntent(t *testing.T) {
	pkt := make([]byte, 48)
	pkt[0] = (2 << 3) | 6 // mode 6 (control)
	pkt[1] = 2            // opcode READVAR
	res, _ := (&ntp{}).Handle(context.Background(), pkt, &net.UDPAddr{}, &fakePacketConn{}, config.Listener{})
	if !containsStr(anomaliesOf(res), "ntp-control-query") {
		t.Errorf("mode-6 not flagged: %v", anomaliesOf(res))
	}
	if it, _ := res.Meta["intent"].(string); !strings.Contains(it, "READVAR") {
		t.Errorf("intent = %q", it)
	}
}

// SNMP SET = config-write intent; a request touching CISCO-CONFIG-COPY-MIB =
// running-config exfil; default community is flagged.
func TestSNMPIntentAndConfigExfil(t *testing.T) {
	h := &snmp{arch: testSNMPArch(t)}
	cfg := config.Listener{SNMP: config.SNMPListener{MIBProfile: "host"}}
	src := &net.UDPAddr{IP: net.IPv4(9, 9, 9, 9), Port: 5}

	set := &g.SnmpPacket{Version: g.Version2c, Community: "private", PDUType: g.SetRequest, RequestID: 1,
		Variables: []g.SnmpPDU{{Name: "1.3.6.1.4.1.9.9.96.1.1.1.1.14.1", Type: g.Integer, Value: 1}}}
	b, err := set.MarshalMsg()
	if err != nil {
		t.Fatal(err)
	}
	res, _ := h.Handle(context.Background(), b, src, &fakePacketConn{}, cfg)
	an := anomaliesOf(res)
	for _, want := range []string{"snmp-set-attempt", "snmp-config-exfil", "snmp-default-community"} {
		if !containsStr(an, want) {
			t.Errorf("SET/config-exfil anomalies missing %q: %v", want, an)
		}
	}
	if it, _ := res.Meta["intent"].(string); !strings.Contains(it, "CONFIG-COPY") || !strings.Contains(it, "private") {
		t.Errorf("intent = %q, want config-copy + default-community note", it)
	}
}

// DNS SIG (qtype 24) and TKEY (qtype 249) queries are exploit-probe vectors
// carrying their CVEs + an intent label.
func TestDNSExploitQtypes(t *testing.T) {
	check := func(qtype uint16, wantAnom, wantIntent string) {
		msg := buildDNSMsgOpts(dnsMsgOpts{name: "x.example.com", qtype: qtype})
		q, ok := parseDNSQuery(msg)
		if !ok {
			t.Fatalf("parse qtype %d", qtype)
		}
		res := &Result{Meta: map[string]any{}}
		dnsApplyDetections(res, msg, q)
		if !containsStr(anomaliesOf(*res), wantAnom) {
			t.Errorf("qtype %d missing anomaly %q: %v", qtype, wantAnom, anomaliesOf(*res))
		}
		if it, _ := res.Meta["intent"].(string); !strings.Contains(it, wantIntent) {
			t.Errorf("qtype %d intent = %q, want %q", qtype, it, wantIntent)
		}
	}
	check(24, "cve:CVE-2020-1350", "SIGRed")
	check(249, "cve:CVE-2015-5477", "TKEY")
}
