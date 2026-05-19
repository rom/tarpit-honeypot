//go:build !linux

package honeynet

import (
	"context"
	"errors"
)

func startICMPResponder(_ context.Context, _ string, _ *Topology) error {
	return errors.New("icmp_responder: linux-only")
}
