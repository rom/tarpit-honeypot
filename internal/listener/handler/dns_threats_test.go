package handler

import (
	"encoding/binary"
	"strings"
	"testing"
)

// dnsMsgOpts configures buildDNSMsgOpts to exercise the threat detectors.
type dnsMsgOpts struct {
	name           string
	qtype, qclass  uint16
	flags1         byte   // bits: QR(0x80) | opcode<<3 | RD(0x01); 0 -> 0x01 (RD)
	qd, an, ns, ar uint16 // header counts; qd 0 -> 1
	optSize        uint16 // when >0, append an EDNS(0) OPT with this UDP size
	optDO          bool
	optVer         byte
}

func buildDNSMsgOpts(o dnsMsgOpts) []byte {
	if o.qclass == 0 {
		o.qclass = 1
	}
	qd := o.qd
	if qd == 0 {
		qd = 1
	}
	f1 := o.flags1
	if f1 == 0 {
		f1 = 0x01
	}
	msg := make([]byte, 12)
	binary.BigEndian.PutUint16(msg[0:2], 0x1234)
	msg[2] = f1
	binary.BigEndian.PutUint16(msg[4:6], qd)
	binary.BigEndian.PutUint16(msg[6:8], o.an)
	binary.BigEndian.PutUint16(msg[8:10], o.ns)
	for _, label := range strings.Split(o.name, ".") {
		if label == "" {
			continue
		}
		msg = append(msg, byte(len(label)))
		msg = append(msg, label...)
	}
	msg = append(msg, 0) // root
	msg = binary.BigEndian.AppendUint16(msg, o.qtype)
	msg = binary.BigEndian.AppendUint16(msg, o.qclass)
	ar := o.ar
	if o.optSize > 0 {
		ar++
		msg = append(msg, 0x00)                             // OPT owner = root
		msg = binary.BigEndian.AppendUint16(msg, 41)        // TYPE = OPT
		msg = binary.BigEndian.AppendUint16(msg, o.optSize) // CLASS = UDP size
		var flags16 uint16
		if o.optDO {
			flags16 = 0x8000
		}
		msg = append(msg, 0x00)     // extended RCODE
		msg = append(msg, o.optVer) // EDNS version
		msg = binary.BigEndian.AppendUint16(msg, flags16)
		msg = binary.BigEndian.AppendUint16(msg, 0) // RDLEN
	}
	binary.BigEndian.PutUint16(msg[10:12], ar)
	return msg
}

func dnsHasMarker(list []string, m string) bool {
	for _, e := range list {
		if e == m {
			return true
		}
	}
	return false
}

func TestDNSThreatMarkers(t *testing.T) {
	enc40 := strings.Repeat("ab12cd34", 5) // 40 chars, base32/hex-looking
	manyLabels := strings.Repeat("z.", 25) + "example.com"
	repeated := strings.Repeat("a.", 10) + "example.com"

	cases := []struct {
		desc string
		opts dnsMsgOpts
		want string
	}{
		{"QR set", dnsMsgOpts{name: "a.example.com", qtype: 1, flags1: 0x80}, "dns-response-as-query"},
		{"IQUERY", dnsMsgOpts{name: "a.example.com", qtype: 1, flags1: 0x08}, "dns-inverse-query"},
		{"NOTIFY", dnsMsgOpts{name: "a.example.com", qtype: 1, flags1: 0x20}, "dns-notify-opcode"},
		{"UPDATE", dnsMsgOpts{name: "a.example.com", qtype: 1, flags1: 0x28}, "dns-dynamic-update"},
		{"multi-question", dnsMsgOpts{name: "a.example.com", qtype: 1, qd: 2}, "dns-multi-question"},
		{"prestuffed", dnsMsgOpts{name: "a.example.com", qtype: 1, an: 1}, "dns-prestuffed-answers"},
		{"additional-stuffing", dnsMsgOpts{name: "a.example.com", qtype: 1, ar: 2}, "dns-additional-stuffing"},
		{"nonstandard-class", dnsMsgOpts{name: "a.example.com", qtype: 1, qclass: 2}, "dns-nonstandard-class"},
		{"chaos-class", dnsMsgOpts{name: "version.bind", qtype: 16, qclass: 3}, "dns-chaos-class"},
		{"dnssec-recon", dnsMsgOpts{name: "example.com", qtype: 48}, "dns-dnssec-recon"},
		{"nsec-walk", dnsMsgOpts{name: "example.com", qtype: 47}, "dns-nsec-walk"},
		{"svcb-probe", dnsMsgOpts{name: "example.com", qtype: 64}, "dns-svcb-probe"},
		{"caa-probe", dnsMsgOpts{name: "example.com", qtype: 257}, "dns-caa-probe"},
		{"null-record", dnsMsgOpts{name: "t.example.com", qtype: 10}, "dns-null-record"},
		{"cname-tunnel", dnsMsgOpts{name: strings.Repeat("x", 35) + ".example.com", qtype: 5}, "dns-cname-tunnel"},
		{"mail-policy", dnsMsgOpts{name: "_dmarc.example.com", qtype: 16}, "dns-mail-policy-probe"},
		{"ad-srv", dnsMsgOpts{name: "_ldap._tcp.dc._msdcs.example.com", qtype: 33}, "dns-srv-ad-discovery"},
		{"ptr-sweep", dnsMsgOpts{name: "1.0.0.10.in-addr.arpa", qtype: 12}, "dns-ptr-reverse-sweep"},
		{"internal-tld", dnsMsgOpts{name: "fileserver.corp", qtype: 1}, "dns-internal-tld-leak"},
		{"wpad", dnsMsgOpts{name: "wpad.example.com", qtype: 1}, "dns-wpad-probe"},
		{"isatap", dnsMsgOpts{name: "isatap.example.com", qtype: 1}, "dns-isatap-probe"},
		{"oob", dnsMsgOpts{name: "abc.oast.fun", qtype: 1}, "dns-oob-interaction"},
		{"rebind", dnsMsgOpts{name: "10.0.0.1.nip.io", qtype: 1}, "dns-rebind-lookup"},
		{"many-labels", dnsMsgOpts{name: manyLabels, qtype: 1}, "dns-many-labels"},
		{"long-encoded", dnsMsgOpts{name: enc40 + ".t.example.com", qtype: 16}, "dns-long-encoded-label"},
		{"repeated-label", dnsMsgOpts{name: repeated, qtype: 1}, "dns-repeated-label"},
		{"random-subdomain", dnsMsgOpts{name: "xkfqplmzvbnq.example.com", qtype: 1}, "dns-random-subdomain"},
		{"edns-large", dnsMsgOpts{name: "example.com", qtype: 1, optSize: 4096}, "dns-edns-large-udpsize"},
		{"edns-version", dnsMsgOpts{name: "example.com", qtype: 1, optSize: 1232, optVer: 1}, "dns-edns-version-nonzero"},
		{"dnssec-amp", dnsMsgOpts{name: "example.com", qtype: 255, optSize: 1232, optDO: true}, "dns-dnssec-amplification"},
	}
	if len(cases) != 30 {
		t.Fatalf("expected 30 detection cases, have %d", len(cases))
	}
	for _, c := range cases {
		msg := buildDNSMsgOpts(c.opts)
		q, ok := parseDNSQuery(msg)
		if !ok {
			t.Errorf("%s: query did not parse", c.desc)
			continue
		}
		got := dnsThreatMarkers(msg, q)
		if !dnsHasMarker(got, c.want) {
			t.Errorf("%s: expected marker %q; got %v", c.desc, c.want, got)
		}
	}

	// A vanilla A query must not trip any of the new markers.
	msg := buildDNSMsgOpts(dnsMsgOpts{name: "www.example.com", qtype: 1, optSize: 1232})
	q, _ := parseDNSQuery(msg)
	if got := dnsThreatMarkers(msg, q); len(got) != 0 {
		t.Errorf("benign A query flagged: %v", got)
	}
}
