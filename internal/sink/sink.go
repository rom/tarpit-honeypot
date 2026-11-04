package sink

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/event"
	"github.com/rom/tarpit-honeypot/internal/format"
)

type Sink interface {
	ID() string
	Send(ctx context.Context, ev *event.Event) error
	Close() error
}

func Build(ch config.Channel, dataDir string, jsonMB int) (Sink, error) {
	f, err := format.Get(ch.Format)
	if err != nil {
		return nil, fmt.Errorf("sink %s: %w", ch.ID, err)
	}
	switch ch.Type {
	case "stdout":
		return newStdout(ch.ID, f), nil
	case "jsonlog":
		return newJSONLog(ch.ID, dataDir, jsonMB, f)
	case "webhook":
		return newWebhook(ch, f)
	case "discord":
		return newDiscord(ch)
	case "smtp":
		return newSMTP(ch, f)
	case "syslog":
		return newSyslog(ch, f)
	case "twilio":
		return newTwilio(ch)
	case "sns":
		return newSNS(ch)
	case "snmptrap":
		return newSNMPTrap(ch)
	case "mqtt":
		return newMQTT(ch, f)
	case "slack":
		return newChat(ch, "slack")
	case "teams":
		return newChat(ch, "teams")
	case "elasticsearch", "opensearch":
		return newElasticsearch(ch, f)
	case "splunk_hec":
		return newSplunkHEC(ch, f)
	}
	return nil, fmt.Errorf("sink %s: unknown type %q", ch.ID, ch.Type)
}

// Dests returns the outbound destination(s) — "host:port" and bare "host" — a
// channel will connect to, for building the egress allowlist. Local /
// non-egress channels (stdout, jsonlog, sqlite, local syslog) return nil.
func Dests(ch config.Channel) []string {
	switch ch.Type {
	case "webhook", "mqtt":
		return urlDests(ch.URL)
	case "discord", "slack", "teams", "elasticsearch", "opensearch", "splunk_hec":
		u := ch.URL
		if u == "" && ch.URLEnv != "" {
			u = os.Getenv(ch.URLEnv)
		}
		return urlDests(u)
	case "twilio":
		return []string{"api.twilio.com:443"}
	case "sns":
		if ch.Region == "" {
			return nil
		}
		return []string{net.JoinHostPort("sns."+ch.Region+".amazonaws.com", "443")}
	case "smtp":
		if ch.Host == "" {
			return nil
		}
		return []string{net.JoinHostPort(ch.Host, strconv.Itoa(ch.Port))}
	case "syslog":
		if ch.Network == "tcp" || ch.Network == "tls" || ch.Network == "udp" {
			return addrDests(ch.Address)
		}
	case "snmptrap":
		return addrDests(ch.Address)
	}
	return nil
}

// schemePort maps a URL scheme to its default port, so an allowlist entry is a
// tight host:port (not a bare host that would permit any port on that host).
var schemePort = map[string]string{
	"http": "80", "https": "443", "ws": "80", "wss": "443",
	"tcp": "1883", "mqtt": "1883", "tls": "8883", "ssl": "8883", "mqtts": "8883",
}

// urlDests parses a URL (http/https/tcp/tls/ws/wss) into a single tight
// "host:port" allowlist entry.
func urlDests(raw string) []string {
	if raw == "" {
		return nil
	}
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" {
		return nil
	}
	port := u.Port()
	if port == "" {
		port = schemePort[u.Scheme]
	}
	if port == "" {
		return []string{u.Hostname()} // unknown scheme, no port: fall back to host
	}
	return []string{net.JoinHostPort(u.Hostname(), port)}
}

// addrDests returns a "host:port" address as a single tight allowlist entry.
func addrDests(addr string) []string {
	if addr == "" {
		return nil
	}
	return []string{addr}
}
