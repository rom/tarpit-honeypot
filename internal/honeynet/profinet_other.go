//go:build !linux

package honeynet

import (
	"context"
	"errors"
	"runtime"
)

// PROFINET-DCP needs raw-L2 socket access (AF_PACKET). The non-Linux
// build returns a clean diagnostic instead of a silent no-op.
func startProfinetDCP(_ context.Context, _ ProfinetCfg, _ *Topology, _ ProbeFunc) error {
	return errors.New("profinet_responder: needs AF_PACKET (linux-only); unavailable on " + runtime.GOOS)
}
