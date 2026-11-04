//go:build !tarpit_xdp

package fastpath

import "errors"

// ErrXDPUnavailable is returned by AttachXDP in a normal build: the in-kernel
// XDP tier is compiled in only with the `tarpit_xdp` build tag on Linux and
// requires a compiled BPF object + CAP_BPF/CAP_NET_ADMIN at runtime. The
// default, always-available DoS-resistance tier is the userspace Shaper.
var ErrXDPUnavailable = errors.New("fastpath: XDP tier not built (rebuild with -tags tarpit_xdp on Linux); using the userspace shaper")

// XDP is the handle for an attached in-kernel program. In a normal build it is
// never created; AttachXDP returns ErrXDPUnavailable.
type XDP struct{}

// AttachXDP is a no-op in the default build. With `-tags tarpit_xdp` (Linux)
// the real loader in xdp_linux.go attaches the program to the interface.
func AttachXDP(iface string, _ *Shaper) (*XDP, error) { return nil, ErrXDPUnavailable }

// Available reports whether the in-kernel XDP tier is compiled in.
func Available() bool { return false }

// Close is a no-op.
func (*XDP) Close() error { return nil }
