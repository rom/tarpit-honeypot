//go:build !linux

package honeynet

import (
	"context"
	"errors"
	"runtime"
)

// On non-Linux the ARP responder needs a raw-L2 socket. macOS / BSD
// use /dev/bpf which we haven't ported. The responder stays
// Linux-only; on other platforms operators get L2 presence via
// `ifconfig <iface> alias <ip>` per host or by running the
// responder on a Linux gateway.
func startARPResponder(_ context.Context, _ string, _ *Topology) error {
	return errors.New("arp_responder: needs AF_PACKET (linux-only); on " + runtime.GOOS +
		" use `ifconfig <iface> alias <ip>` per honeynet host or run the responder on a Linux gateway")
}
