//go:build !windows

package sink

import (
	"context"
	"encoding/json"
	"log/syslog"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/event"
)

type syslogSink struct {
	id string
	w  *syslog.Writer
}

func newSyslog(ch config.Channel) (*syslogSink, error) {
	var w *syslog.Writer
	var err error
	priority := syslog.LOG_INFO | syslog.LOG_DAEMON
	switch ch.Network {
	case "local", "":
		w, err = syslog.New(priority, ch.Tag)
	default:
		w, err = syslog.Dial(ch.Network, ch.Address, priority, ch.Tag)
	}
	if err != nil {
		return nil, err
	}
	return &syslogSink{id: ch.ID, w: w}, nil
}

func (s *syslogSink) ID() string { return s.id }

func (s *syslogSink) Send(_ context.Context, ev *event.Event) error {
	b, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	switch ev.Severity {
	case event.SeverityCritical:
		return s.w.Crit(string(b))
	case event.SeverityHigh:
		return s.w.Err(string(b))
	case event.SeverityMedium:
		return s.w.Warning(string(b))
	default:
		return s.w.Info(string(b))
	}
}

func (s *syslogSink) Close() error { return s.w.Close() }
