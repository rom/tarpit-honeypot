//go:build !linux

package honeynet

import (
	"context"
	"errors"
)

func startARPResponder(_ context.Context, _ string, _ *Topology) error {
	return errors.New("arp_responder: linux-only")
}
