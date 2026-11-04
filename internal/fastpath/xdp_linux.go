//go:build linux && tarpit_xdp

package fastpath

import (
	"errors"
	"sync"
)

// This file is the integration skeleton for the in-kernel eBPF/XDP tier. It is
// compiled only with `-tags tarpit_xdp` on Linux and is intentionally NOT wired
// to a BPF toolchain or external dependency in this tree — the compiled XDP
// object and the loader (cilium/ebpf or libbpf) are supplied by the build that
// opts in. Keeping the loader out of the default build means `go build ./...`
// never needs a kernel, clang/LLVM, CAP_BPF, or a NIC, and the honeypot always
// has the working userspace Shaper.
//
// Design (see docs/xdp-fastpath.md):
//
//	XDP program (xdp_fastpath.c, compiled to xdp_fastpath.o):
//	  - attached at the driver RX hook on the honeypot interface;
//	  - looks each source IP up in a BPF_MAP_TYPE_LRU_HASH "drop" map and
//	    returns XDP_DROP for a hit (the hard blocklist), else
//	  - charges a per-source token bucket held in a second LRU_HASH map
//	    (tokens refilled from a timestamp, same math as the Shaper) and
//	    returns XDP_DROP when the bucket is empty, else XDP_PASS;
//	  - bumps per-verdict counters in a PERCPU_ARRAY the Go side reads for Stats.
//
//	Go side (this file):
//	  - loads xdp_fastpath.o, attaches it to iface, and mirrors the Shaper's
//	    drop-set into the "drop" map so userspace and kernel agree on blocks;
//	  - exposes the kernel counters through Stats().
//
// Until that object + loader are provided, AttachXDP returns a clear error so
// an operator who enables the tag without the artifacts is told plainly rather
// than silently getting the userspace path.

// errXDPNotProvisioned is returned when the tag is on but the compiled BPF
// object / loader have not been supplied by the build.
var errXDPNotProvisioned = errors.New("fastpath: tarpit_xdp build has no xdp_fastpath.o / loader provisioned — see docs/xdp-fastpath.md; falling back to the userspace shaper")

// XDP is the handle for an attached program (fields added by the opt-in build).
type XDP struct {
	mu    sync.Mutex
	iface string
	// link, objs, maps … are added here by the build that provides the loader.
}

// Available reports whether the in-kernel XDP tier is compiled in (it is, under
// this tag) — note AttachXDP still needs the provisioned object to succeed.
func Available() bool { return true }

// AttachXDP attaches the XDP program to iface and mirrors the Shaper's drop-set
// into the kernel map. The loader is build-provided; without it this returns
// errXDPNotProvisioned so the caller keeps using the userspace Shaper.
func AttachXDP(iface string, _ *Shaper) (*XDP, error) {
	return nil, errXDPNotProvisioned
}

// Close detaches the program and releases the maps.
func (x *XDP) Close() error { return nil }
