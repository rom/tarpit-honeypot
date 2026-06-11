package handler

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/safe"
)

// ssdp listens for UPnP discovery (SSDP) requests — UDP port 1900,
// HTTP-over-UDP. Scanners typically send M-SEARCH multicasts that
// look like:
//
//	M-SEARCH * HTTP/1.1
//	HOST: 239.255.255.250:1900
//	MAN: "ssdp:discover"
//	MX: 1
//	ST: upnp:rootdevice
//
// We reply with a fake-but-plausible NOTIFY referencing a router-shaped
// USN so IoT scanners think they've discovered a Cisco / TP-Link / etc.
type ssdp struct{ lim *udpReflectLimiter }

func (s *ssdp) Name() string { return "ssdp" }

func (s *ssdp) Handle(_ context.Context, payload []byte, src net.Addr, pc net.PacketConn, cfg config.Listener) (Result, error) {
	res := Result{Payload: append([]byte(nil), payload...), Meta: map[string]any{}}
	lines := strings.Split(string(payload), "\r\n")
	if len(lines) < 1 {
		return res, nil
	}
	reqLine := lines[0]
	res.Meta["request_line"] = reqLine
	res.Meta["protocol_name"] = "UPnP SSDP"
	st, man := "", ""
	for _, line := range lines[1:] {
		// Absurdly long SSDP header lines are the libupnp "Unplug Don't Play"
		// SSDP stack-overflow vector (CVE-2012-5958/5959). The UDP path surfaces
		// this as an anomaly (+ CWE) rather than a cve: event (CVEHits is the
		// TCP-only channel); the CVE stays catalogued for advisory / list-cves.
		if len(line) > 700 {
			flagAnomaly(&res, "upnp-libupnp-overflow")
			noteCWE(&res, "CWE-120") // classic buffer overflow
		}
		lower := strings.ToLower(line)
		switch {
		case strings.HasPrefix(lower, "st:"):
			st = strings.TrimSpace(line[3:])
			res.Meta["st"] = st
		case strings.HasPrefix(lower, "user-agent:"):
			res.Meta["user_agent"] = strings.TrimSpace(line[11:])
		case strings.HasPrefix(lower, "mx:"):
			res.Meta["mx"] = strings.TrimSpace(line[3:])
		case strings.HasPrefix(lower, "man:"):
			man = strings.TrimSpace(line[4:])
			res.Meta["man"] = man
		}
	}
	if !strings.HasPrefix(strings.ToUpper(reqLine), "M-SEARCH") {
		return res, nil
	}
	// Intent: an ssdp:all M-SEARCH is the high-amplification reflection probe;
	// any other ssdp:discover is internet-wide UPnP device enumeration.
	if strings.EqualFold(st, "ssdp:all") {
		setIfEmpty(res.Meta, "intent", "UPnP/SSDP ssdp:all M-SEARCH — reflection/amplification probe + full UPnP enumeration")
	} else {
		setIfEmpty(res.Meta, "intent", "UPnP/SSDP discovery probe — enumerating internet-facing UPnP devices")
	}
	// Only answer a complete ssdp:discover (MAN + ST present), and never
	// amplify — a minimal/forged "M-SEARCH" probe with a spoofed source is
	// the classic SSDP reflection vector.
	if st == "" || !strings.Contains(strings.ToLower(man), "ssdp:discover") {
		res.Meta["incomplete_msearch"] = true
		return res, nil
	}
	// ST: ssdp:all asks every device to enumerate every service — the highest
	// amplification factor and the hallmark of an SSDP reflection probe.
	if strings.EqualFold(st, "ssdp:all") {
		flagAnomaly(&res, "ssdp-all-amplification")
	}
	location := "http://192.168.1.1:1900/rootDesc.xml"
	usn := "uuid:tarpit-honeypot-1234::upnp:rootdevice"
	server := "Linux/3.14 UPnP/1.0 TPLink-Router/2.0"
	// SECURITY: ST: is taken from the attacker's M-SEARCH request and
	// reflected verbatim into our reply. Without sanitization, CRLF
	// in ST: lets an off-path attacker (UDP source-IP-spoofable) inject
	// arbitrary HTTP-shaped headers + body into a packet sent to any
	// IP they choose — a one-shot reflection/amplification primitive
	// against a third party. SanitizeHeader strips CR/LF/NUL.
	safeST := safe.SanitizeHeader(st)
	reply := fmt.Sprintf("HTTP/1.1 200 OK\r\n"+
		"CACHE-CONTROL: max-age=120\r\n"+
		"DATE: \r\n"+
		"EXT:\r\n"+
		"LOCATION: %s\r\n"+
		"SERVER: %s\r\n"+
		"ST: %s\r\n"+
		"USN: %s\r\n\r\n",
		location, server, safeST, usn)
	if !s.lim.allow() {
		res.Meta["rate_limited"] = true
		_ = cfg
		return res, nil
	}
	if _, err := pc.WriteTo([]byte(reply), src); err != nil {
		res.Meta["write_err"] = err.Error()
	}
	res.BannerSent = "ssdp M-SEARCH reply"
	_ = cfg
	return res, nil
}
