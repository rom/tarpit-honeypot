package listener

import (
	"context"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/event"
)

// Listener is something that emits events to the bus until ctx is cancelled.
type Listener interface {
	ID() string
	Start(ctx context.Context, bus chan<- *event.Event) error
}

func Build(l config.Listener, sensorName string) (Listener, error) {
	switch l.Proto {
	case "tcp":
		return newTCP(l, sensorName)
	case "udp":
		return newUDP(l, sensorName)
	}
	// Validation already rejected this; defensive only.
	return nil, errUnknownProto
}
