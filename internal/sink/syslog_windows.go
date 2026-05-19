//go:build windows

package sink

import (
	"errors"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/format"
)

// Stdlib log/syslog is Unix-only.

func newSyslog(_ config.Channel, _ format.Formatter) (Sink, error) {
	return nil, errors.New("syslog channel not supported on windows")
}
