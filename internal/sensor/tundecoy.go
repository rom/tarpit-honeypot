package sensor

import (
	"encoding/base64"
	"fmt"
	"net"

	"github.com/rom/tarpit-honeypot/internal/archetype"
	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/event"
	"github.com/rom/tarpit-honeypot/internal/tcpstack"
	"github.com/rom/tarpit-honeypot/internal/tunnet"
)

// buildTUNDecoys turns each honeynet host into a userspace-TCP decoy: the
// OS fingerprint its SYN-ACK is shaped to (from the archetype family) and
// the bytes each declared service speaks. Hosts with no services still get
// an entry (Profile set, no open ports) so closed-port RSTs carry the
// host's archetype TTL — keeping ICMP, RST and SYN-ACK fingerprints
// consistent for nmap -O / p0f.
func buildTUNDecoys(hosts []config.HoneynetHost) map[string]tunnet.HostDecoy {
	out := make(map[string]tunnet.HostDecoy, len(hosts))
	for _, h := range hosts {
		if h.IP == "" {
			continue
		}
		prof := archetype.Lookup(h.Archetype)
		if prof == nil {
			prof = archetype.Lookup(h.OS)
		}
		fam := ""
		if prof != nil {
			fam = prof.Family
		}
		osp := tcpstack.ProfileFor(fam)
		// Match the SYN-ACK TTL to the host's ICMP persona (which may be an
		// archetype override) so every synthesized reply agrees.
		if prof != nil {
			if ttl := prof.ICMPTTL(); ttl > 0 && ttl <= 255 {
				osp.TTL = uint8(ttl)
			}
		}
		d := tunnet.HostDecoy{
			Profile: osp,
			Ports:   map[uint16]bool{},
			Banners: map[uint16][]byte{},
			Replies: map[uint16][]byte{},
		}
		for _, svc := range h.Services {
			if svc.Port <= 0 || svc.Port > 65535 {
				continue
			}
			port := uint16(svc.Port)
			d.Ports[port] = true
			banner, reply := decoyBytes(prof, svc)
			if len(banner) > 0 {
				d.Banners[port] = banner
			}
			if len(reply) > 0 {
				d.Replies[port] = reply
			}
		}
		out[h.IP] = d
	}
	return out
}

// decoyBytes derives the wire bytes a service presents through the userspace
// stack. Server-first services (SSH/FTP/SMTP/Telnet) return a banner sent
// right after the handshake; HTTP returns a canned reply to the first
// request. An explicit service Banner overrides the archetype default.
// HTTPS is intentionally accept-then-silence (the stack can't terminate
// TLS) — the port still fingerprints as open.
func decoyBytes(prof *archetype.Profile, svc config.HoneynetService) (banner, reply []byte) {
	handler := svc.Handler
	if handler == "" {
		handler = handlerForPort(svc.Port)
	}
	switch handler {
	case "ssh":
		s := svc.Banner
		if s == "" {
			s = prof.SSHBanner()
		}
		if s != "" {
			banner = []byte(s + "\r\n")
		}
	case "ftp":
		s := svc.Banner
		if s == "" {
			s = prof.FTPBanner()
		}
		if s != "" {
			banner = []byte(s + "\r\n")
		}
	case "smtp":
		s := svc.Banner
		if s == "" {
			s = smtpGreeting(prof)
		}
		if s != "" {
			banner = []byte(s + "\r\n")
		}
	case "telnet":
		s := svc.Banner
		if s == "" {
			s = prof.TelnetBanner()
		}
		if s != "" {
			banner = []byte(s) // telnet banners already carry their own CRLFs
		}
	case "http":
		reply = httpDecoyReply(prof)
	case "https":
		// TLS handshake is out of scope for the userspace stack.
	default:
		if svc.Banner != "" {
			banner = []byte(svc.Banner + "\r\n")
		}
	}
	return banner, reply
}

// handlerForPort infers a handler from a well-known port when a service
// declares none.
func handlerForPort(port int) string {
	switch port {
	case 22:
		return "ssh"
	case 21:
		return "ftp"
	case 23:
		return "telnet"
	case 25, 587:
		return "smtp"
	case 80, 8080:
		return "http"
	case 443, 8443:
		return "https"
	}
	return ""
}

// tcpDecoyEmitter returns the callback the TUN adapter uses to publish
// userspace-stack events onto the sensor bus. Handshakes and captured
// requests against virtual hosts are low-severity telemetry; malformed /
// illegal packets are medium and carry their markers as anomalies so the
// protocol_violation correlator and the UI surface them. The bus send is
// non-blocking — under a flood we drop rather than stall the reader loop.
func (s *Sensor) tcpDecoyEmitter(netID string) func(tcpstack.Event) {
	return func(ev tcpstack.Event) {
		rule := ""
		sev := event.SeverityLow
		var anomalies []string
		var payloadB64 string
		var payloadLen int
		meta := map[string]any{"honeynet": netID}
		switch ev.Kind {
		case tcpstack.EventHandshake:
			rule = "honeynet:tcp_connect"
		case tcpstack.EventRequest:
			rule = "honeynet:tcp_request"
			payloadLen = len(ev.Payload)
			payloadB64 = base64.StdEncoding.EncodeToString(ev.Payload)
		case tcpstack.EventMalformed:
			rule = "honeynet:tcp_malformed"
			sev = event.SeverityMedium
			anomalies = ev.Markers
			meta["anomalies"] = ev.Markers
			payloadLen = len(ev.Raw)
			payloadB64 = base64.StdEncoding.EncodeToString(ev.Raw)
			// A LAND packet (source == destination) is a recognized
			// endpoint-DoS CVE, not just a crafted probe — promote it to
			// its own high-severity rule with the CVE reference.
			if markersContain(ev.Markers, "tcp-land") {
				rule = "honeynet:tcp_land"
				sev = event.SeverityHigh
				meta["cve"] = "CVE-1999-0016"
			}
		default:
			return
		}
		e := &event.Event{
			ID:            event.NewID(),
			Time:          timeNow(),
			Sensor:        s.name,
			RuleID:        rule,
			Severity:      sev,
			Proto:         "tcp",
			Source:        event.Endpoint{IP: ipString(ev.SrcIP), Port: int(ev.SrcPort)},
			Dest:          event.Endpoint{IP: ipString(ev.DstIP), Port: int(ev.DstPort)},
			Anomalies:     anomalies,
			PayloadBase64: payloadB64,
			PayloadLen:    payloadLen,
			Meta:          meta,
		}
		select {
		case s.bus <- e:
		default:
		}
	}
}

func ipString(b [4]byte) string { return net.IP(b[:]).String() }

func markersContain(markers []string, want string) bool {
	for _, m := range markers {
		if m == want {
			return true
		}
	}
	return false
}

func smtpGreeting(prof *archetype.Profile) string {
	host, product := "mail", ""
	if prof != nil {
		if prof.SMTPHost() != "" {
			host = prof.SMTPHost()
		}
		product = prof.SMTPProduct()
	}
	if product != "" {
		return "220 " + host + " ESMTP " + product
	}
	return "220 " + host + " ESMTP"
}

func httpDecoyReply(prof *archetype.Profile) []byte {
	server, title := "Apache", "Index"
	var body string
	if prof != nil {
		if prof.HTTPServer() != "" {
			server = prof.HTTPServer()
		}
		if prof.HTTPTitle() != "" {
			title = prof.HTTPTitle()
		}
		body = prof.HTTPBodyHTML()
	}
	if body == "" {
		body = "<html><head><title>" + title + "</title></head><body><h1>" + title + "</h1></body></html>"
	}
	hdr := "HTTP/1.1 200 OK\r\n" +
		"Server: " + server + "\r\n" +
		"Content-Type: text/html; charset=UTF-8\r\n" +
		fmt.Sprintf("Content-Length: %d\r\n", len(body)) +
		"Connection: close\r\n\r\n"
	return []byte(hdr + body)
}
