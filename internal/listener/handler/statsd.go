package handler

import (
	"context"
	"net"
	"strings"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/safe"
)

// statsd emulates a StatsD metrics intake (UDP 8125). An internet-exposed
// StatsD accepts unauthenticated "name:value|type" datagrams — useful to
// fingerprint and to catch metric-injection / reconnaissance. It is
// capture-only: it NEVER replies (a UDP response to a spoofable source would be
// a reflection/amplification primitive).
type statsd struct{}

func (s *statsd) Name() string { return "statsd" }

func (s *statsd) Handle(_ context.Context, payload []byte, _ net.Addr, _ net.PacketConn, cfg config.Listener) (Result, error) {
	res := Result{Payload: append([]byte(nil), payload...), Meta: map[string]any{}}
	lines := strings.Split(strings.TrimSpace(string(payload)), "\n")
	n := 0
	for _, l := range lines {
		if strings.TrimSpace(l) != "" {
			n++
		}
	}
	res.Meta["statsd_metrics"] = n
	if n > 0 {
		res.Meta["statsd_first"] = safe.SanitizeForLog(strings.TrimSpace(lines[0]))
		flagAnomaly(&res, "statsd-metric-received")
	}
	_ = cfg
	return res, nil // no reply — reflection-safe
}
