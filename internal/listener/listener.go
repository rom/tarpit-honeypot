package listener

import (
	"context"

	"github.com/rom/tarpit-honeypot/internal/capture"
	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/event"
)

// Listener is something that emits events to the bus until ctx is cancelled.
type Listener interface {
	ID() string
	Start(ctx context.Context, bus chan<- *event.Event) error
}

func Build(l config.Listener, sensorName, dataDir string, capMgr *capture.Manager) (Listener, error) {
	switch l.Proto {
	case "tcp":
		return newTCP(l, sensorName, dataDir, capMgr)
	case "udp":
		return newUDP(l, sensorName)
	}
	return nil, errUnknownProto
}
