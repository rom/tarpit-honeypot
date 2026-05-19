//go:build windows

package sink

import (
	"errors"

	"github.com/rom/tarpit-honeypot/internal/config"
)

// Stdlib log/syslog is Unix-only. Windows support lands in v0.3 alongside
// the service installer; until then a syslog channel is a config error on
// Windows rather than a silent no-op.

func newSyslog(_ config.Channel) (Sink, error) {
	return nil, errors.New("syslog channel not supported on windows (planned for v0.3)")
}
