package sink

import (
	"context"
	"fmt"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/event"
)

type Sink interface {
	ID() string
	Send(ctx context.Context, ev *event.Event) error
	Close() error
}

func Build(ch config.Channel, dataDir string, jsonMB int) (Sink, error) {
	switch ch.Type {
	case "stdout":
		return newStdout(ch.ID), nil
	case "jsonlog":
		return newJSONLog(ch.ID, dataDir, jsonMB)
	case "webhook":
		return newWebhook(ch)
	case "smtp":
		return newSMTP(ch)
	case "syslog":
		return newSyslog(ch)
	}
	return nil, fmt.Errorf("sink %s: unknown type %q", ch.ID, ch.Type)
}
