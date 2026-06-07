package handler

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"testing"

	"github.com/rom/tarpit-honeypot/internal/config"
)

// buildCHAOSQuery builds a CHAOS-class (QCLASS=3) TXT query for name.
func buildCHAOSQuery(name string) []byte {
	msg := make([]byte, 12)
	binary.BigEndian.PutUint16(msg[0:2], 0x4321)
	msg[2] = 0x01
	binary.BigEndian.PutUint16(msg[4:6], 1)
	for _, label := range bytes.Split([]byte(name), []byte(".")) {
		msg = append(msg, byte(len(label)))
		msg = append(msg, label...)
	}
	msg = append(msg, 0)
	msg = binary.BigEndian.AppendUint16(msg, 16) // TXT
	msg = binary.BigEndian.AppendUint16(msg, 3)  // CHAOS
	return msg
}

func TestDNSChaosDualStack(t *testing.T) {
	cases := map[string]string{
		"version.bind":  "9.8.1-P1",
		"hostname.bind": "ns1",
		"id.server":     "ns1",
	}
	srcs := map[string]net.Addr{
		"ipv4": &net.UDPAddr{IP: net.IPv4(203, 0, 113, 7), Port: 5353},
		"ipv6": &net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: 5353},
	}
	for fam, src := range srcs {
		for name, want := range cases {
			pc := &fakePacketConn{}
			res, err := (&dnsHandler{}).Handle(context.Background(), buildCHAOSQuery(name), src, pc, config.Listener{})
			if err != nil {
				t.Fatalf("%s/%s: %v", fam, name, err)
			}
			if len(pc.written) != 1 {
				t.Errorf("%s/%s: expected 1 reply; got %d", fam, name, len(pc.written))
				continue
			}
			if !bytes.Contains(pc.written[0], []byte(want)) {
				t.Errorf("%s/%s: reply missing %q", fam, name, want)
			}
			if !hasAnom(res, "dns-chaos-class") {
				t.Errorf("%s/%s: CHAOS recon not flagged: %v", fam, name, res.Meta["anomalies"])
			}
		}
	}
}
