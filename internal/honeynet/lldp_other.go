//go:build !linux

package honeynet

import (
	"context"
	"errors"
)

func startLLDPResponder(_ context.Context, _ LLDPCfg, _ *Topology) error {
	return errors.New("lldp_responder: Linux-only (AF_PACKET + CAP_NET_RAW required)")
}
