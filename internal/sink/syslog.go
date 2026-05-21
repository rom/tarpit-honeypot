//go:build !windows

package sink

import (
	"context"
	"log/syslog"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/event"
	"github.com/rom/tarpit-honeypot/internal/format"
)

type syslogSink struct {
	id        string
	w         *syslog.Writer
	formatter format.Formatter
}

func newSyslog(ch config.Channel, f format.Formatter) (Sink, error) {
	// tcp / tls use the RFC 5424 + octet-counting stream sink (log/syslog
	// can't do TLS and uses BSD framing).
	if ch.Network == "tcp" || ch.Network == "tls" {
		return newStreamSyslog(ch, f)
	}
	var w *syslog.Writer
	var err error
	priority := syslog.LOG_INFO | syslog.LOG_DAEMON
	switch ch.Network {
	case "local", "":
		w, err = syslog.New(priority, ch.Tag)
	default: // udp | unix
		w, err = syslog.Dial(ch.Network, ch.Address, priority, ch.Tag)
	}
	if err != nil {
		return nil, err
	}
	return &syslogSink{id: ch.ID, w: w, formatter: f}, nil
}

func (s *syslogSink) ID() string { return s.id }

func (s *syslogSink) Send(_ context.Context, ev *event.Event) error {
	b, err := s.formatter.Format(ev)
	if err != nil {
		return err
	}
	msg := string(b)
	switch ev.Severity {
	case event.SeverityCritical:
		return s.w.Crit(msg)
	case event.SeverityHigh:
		return s.w.Err(msg)
	case event.SeverityMedium:
		return s.w.Warning(msg)
	default:
		return s.w.Info(msg)
	}
}

func (s *syslogSink) Close() error { return s.w.Close() }
