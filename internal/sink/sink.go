package sink

import (
	"context"
	"fmt"

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
	}
	return nil, fmt.Errorf("sink %s: unknown type %q", ch.ID, ch.Type)
}
