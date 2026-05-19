// Package sniffer is the layer-2 observer. It opens an AF_PACKET socket on
// Linux, filters for ARP frames, and emits events for ARP scans (one source
// MAC asking about many distinct IPs) and unsolicited ARP replies (potential
// ARP-cache poisoning).
//
// Linux-only. Other platforms get a stub that errors at New so the sensor
// logs a clear "disabled on this platform" line and continues.
package sniffer

import (
	"context"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/event"
)

// Sniffer is the cross-platform interface. The platform file decides the
// concrete implementation; on non-Linux the constructor returns an error
// rather than a working object.
type Sniffer interface {
	Run(ctx context.Context, bus chan<- *event.Event) error
}

// New is implemented in sniffer_linux.go / sniffer_other.go.
func New(cfg config.Sniffer, sensorName string) (Sniffer, error) {
	return newImpl(cfg, sensorName)
}
