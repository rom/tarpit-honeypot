//go:build !linux

package tunnet

import (
	"context"
	"errors"
	"runtime"

	"github.com/rom/tarpit-honeypot/internal/tcpstack"
)

// macOS supports utun devices via PF_SYSTEM + UTUN_CONTROL_NAME and a
// 4-byte AF-family prefix on each packet. A native macOS backend
// hasn't been ported yet; the Linux TUN/TAP code uses a different
// API (/dev/net/tun + ioctls + raw IP frames). When that backend
// arrives this file shrinks to a !linux && !darwin guard.
//
// In the meantime, operators on macOS who want L3 honeynet presence
// can use `ifconfig <iface> alias <ip>` per virtual host — the
// kernel handles ARP / ICMP echo for the alias natively and routes
// L4 to whatever sockets the sensor opens. That covers the common
// "make virtual hosts answer ping + accept TCP" need without
// userspace L2.

type Config struct {
	DeviceName string
	CIDRs      []string
	HostIPs    []string
	MTU        int
	Personas   map[string]int // host IP -> initial IP TTL (0 = default 64)
	Hosts      map[string]HostDecoy
	Emit       func(tcpstack.Event)
}

// HostDecoy mirrors the Linux definition so the sensor builds the same
// config on every platform; the userspace TCP stack is Linux-only at
// runtime (this backend returns an error from New).
type HostDecoy struct {
	Profile tcpstack.OSProfile
	Ports   map[uint16]bool
	Banners map[uint16][]byte
	Replies map[uint16][]byte
}

type Adapter struct{}

func New(_ Config) (*Adapter, error) {
	return nil, errors.New("tunnet: TUN/utun adapter not implemented on " + runtime.GOOS +
		" (linux-only today); use `ifconfig alias` per host as a workaround")
}

func (a *Adapter) Run(_ context.Context) error {
	return errors.New("tunnet: not implemented on " + runtime.GOOS)
}
func (a *Adapter) Close() error { return nil }
