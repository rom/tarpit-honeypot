package sensor

import (
	"testing"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/event"
	"github.com/rom/tarpit-honeypot/internal/tcpstack"
)

func TestBuildTUNDecoys(t *testing.T) {
	hosts := []config.HoneynetHost{
		{IP: ""}, // skipped (no IP)
		{IP: "10.0.0.1", Archetype: "ubuntu-24-04-lts", Services: []config.HoneynetService{
			{Port: 22, Handler: "ssh"},
			{Port: 21, Handler: "ftp"},
			{Port: 25, Handler: "smtp"},
			{Port: 23, Handler: "telnet"},
			{Port: 80, Handler: "http"},
			{Port: 443, Handler: "https"},  // open, no bytes
			{Port: 9999, Banner: "CUSTOM"}, // default branch
			{Port: 0},                      // skipped (bad port)
			{Port: 70000},                  // skipped (bad port)
		}},
		{IP: "10.0.0.2"}, // no services → profile only, no ports
	}
	d := buildTUNDecoys(hosts)
	if _, ok := d[""]; ok {
		t.Error("empty-IP host should be skipped")
	}
	h := d["10.0.0.1"]
	if !h.Ports[22] || !h.Ports[80] || !h.Ports[443] || !h.Ports[9999] {
		t.Errorf("expected ports 22/80/443/9999 open: %v", h.Ports)
	}
	if h.Ports[0] {
		t.Error("out-of-range port 0 must be dropped")
	}
	if len(h.Banners[22]) == 0 {
		t.Error("ssh port should carry a banner")
	}
	if len(h.Replies[80]) == 0 {
		t.Error("http port should carry a reply")
	}
	if len(h.Banners[443]) != 0 || len(h.Replies[443]) != 0 {
		t.Error("https is accept-then-silence: no bytes")
	}
	if string(h.Banners[9999]) != "CUSTOM\r\n" {
		t.Errorf("custom banner = %q", h.Banners[9999])
	}
	if _, ok := d["10.0.0.2"]; !ok {
		t.Error("service-less host should still get a decoy entry")
	}
}

func TestHandlerForPort(t *testing.T) {
	cases := map[int]string{22: "ssh", 21: "ftp", 23: "telnet", 25: "smtp", 587: "smtp", 80: "http", 8080: "http", 443: "https", 8443: "https", 12345: ""}
	for port, want := range cases {
		if got := handlerForPort(port); got != want {
			t.Errorf("handlerForPort(%d) = %q; want %q", port, got, want)
		}
	}
	// decoyBytes falls back to handlerForPort when Handler is empty (nil profile
	// → the service's banner helpers no-op, so no bytes but no panic). The
	// with-profile handler branches are covered by TestBuildTUNDecoys above.
	if b, _ := decoyBytes(nil, config.HoneynetService{Port: 21}); len(b) != 0 {
		t.Errorf("nil-profile ftp decoy produced bytes: %q", b)
	}
}

func TestTCPDecoyEmitter(t *testing.T) {
	s := &Sensor{name: "t", bus: make(chan *event.Event, 16)}
	emit := s.tcpDecoyEmitter("netA")

	emit(tcpstack.Event{Kind: tcpstack.EventHandshake, SrcIP: [4]byte{203, 0, 113, 5}, SrcPort: 44000, DstIP: [4]byte{10, 0, 0, 1}, DstPort: 22, JA4T: "t_fp", JA4L: "l_fp"})
	emit(tcpstack.Event{Kind: tcpstack.EventRequest, SrcIP: [4]byte{203, 0, 113, 5}, DstIP: [4]byte{10, 0, 0, 1}, DstPort: 80, Payload: []byte("GET /")})
	emit(tcpstack.Event{Kind: tcpstack.EventMalformed, SrcIP: [4]byte{203, 0, 113, 5}, DstIP: [4]byte{10, 0, 0, 1}, Markers: []string{"bad-flags"}, Raw: []byte{0x45, 0x00}})
	// LAND packet → promoted rule + CVE, IPv6 address path.
	emit(tcpstack.Event{Kind: tcpstack.EventMalformed, IsV6: true, SrcIP6: [16]byte{0x20, 0x01, 0xd, 0xb8}, DstIP6: [16]byte{0x20, 0x01, 0xd, 0xb8}, Markers: []string{"tcp-land"}, Raw: []byte{0x60}})
	emit(tcpstack.Event{Kind: tcpstack.EventKind("other")}) // ignored

	got := map[string]*event.Event{}
	for i := 0; i < 4; i++ {
		select {
		case e := <-s.bus:
			got[e.RuleID] = e
		default:
			t.Fatalf("expected 4 events, got %d", i)
		}
	}
	if e := got["honeynet:tcp_connect"]; e == nil || e.Meta["ja4t"] != "t_fp" {
		t.Errorf("handshake event missing or no ja4t: %+v", e)
	}
	if e := got["honeynet:tcp_request"]; e == nil || e.PayloadLen != len("GET /") {
		t.Errorf("request event wrong: %+v", e)
	}
	if e := got["honeynet:tcp_malformed"]; e == nil || e.Severity != event.SeverityMedium {
		t.Errorf("malformed event wrong: %+v", e)
	}
	land := got["honeynet:tcp_land"]
	if land == nil || land.Severity != event.SeverityHigh || land.Meta["cve"] != "CVE-1999-0016" {
		t.Errorf("land event wrong: %+v", land)
	}
	if land != nil && land.Source.IP != "2001:db8::" {
		t.Errorf("land source IPv6 = %q; want 2001:db8::", land.Source.IP)
	}
	// the "other" kind produced nothing.
	select {
	case e := <-s.bus:
		t.Errorf("unexpected 5th event: %+v", e)
	default:
	}
}

func TestMarkersContain(t *testing.T) {
	if !markersContain([]string{"a", "tcp-land", "b"}, "tcp-land") {
		t.Error("should find tcp-land")
	}
	if markersContain([]string{"a"}, "x") {
		t.Error("should not find x")
	}
}
