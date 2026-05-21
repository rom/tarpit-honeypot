//go:build windows

package sink

import (
	"errors"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/format"
)

// Stdlib log/syslog is Unix-only, but the tcp/tls stream sink is portable.

func newSyslog(ch config.Channel, f format.Formatter) (Sink, error) {
	if ch.Network == "tcp" || ch.Network == "tls" {
		return newStreamSyslog(ch, f)
	}
	return nil, errors.New("syslog channel on windows: only network=tcp|tls supported")
}
