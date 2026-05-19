//go:build !linux

package canary

import (
	"context"
	"errors"

	"github.com/rom/tarpit-honeypot/internal/event"
)

func startFanotify(_ context.Context, _ []fanotifyTarget, _ string, _ chan<- *event.Event) error {
	return errors.New("fanotify: linux-only")
}
