//go:build !linux

package honeynet

import (
	"context"
	"errors"
	"runtime"
)

// ICMP responder on non-Linux: same raw-socket gap as the ARP
// responder. macOS / BSD have /dev/bpf and SOCK_RAW with
// IPPROTO_ICMP; we haven't ported either. Operators on
// non-Linux can configure host-IP aliases via `ifconfig alias`
// instead — the OS kernel then answers ICMP echo natively.
func startICMPResponder(_ context.Context, _ string, _ *Topology, _ ICMPObserver) error {
	return errors.New("icmp_responder: needs AF_PACKET (linux-only); on " + runtime.GOOS +
		" configure host-IP aliases via `ifconfig <iface> alias <ip>` and the kernel will answer ICMP echo natively")
}
