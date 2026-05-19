//go:build !linux

package honeynet

import (
	"context"
	"errors"
	"runtime"
)

// LLDP / CDP responder needs raw-L2 socket access. macOS / BSD have
// /dev/bpf but the implementation hasn't been ported. Until then,
// LLDP advertising on non-Linux is unavailable; the honeynet still
// works for L3+ traffic via per-host ifconfig aliases — only the
// "show me a believable lldpctl neighbor" deception layer is
// disabled.
func startLLDPResponder(_ context.Context, _ LLDPCfg, _ *Topology) error {
	return errors.New("lldp_responder: needs AF_PACKET (linux-only); on " + runtime.GOOS +
		" LLDP/CDP advertising is unavailable until a /dev/bpf backend ships")
}
