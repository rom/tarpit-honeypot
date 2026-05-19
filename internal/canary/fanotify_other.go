//go:build !linux

package canary

import (
	"context"
	"errors"
	"runtime"

	"github.com/rom/tarpit-honeypot/internal/event"
)

// fanotify is the Linux-specific facility that lets us catch read-only
// OPEN events on a watched honeyfile — the kind a `cat` or `cp` of a
// canary trips even without write access. macOS has FSEvents and
// kqueue (used by fsnotify, which we already wire up for
// write/remove/rename/chmod) but neither surfaces OPEN events to
// userland, so read-detection on macOS isn't possible through public
// APIs.
//
// We return a clean error so the caller falls back to the fsnotify
// path with a logged warning rather than refusing to start the
// watcher entirely.
func startFanotify(_ context.Context, _ []fanotifyTarget, _ string, _ chan<- *event.Event) error {
	return errors.New("fanotify: linux-only; OPEN/read events not detectable on " + runtime.GOOS +
		" (fsnotify still catches write/remove/rename/chmod)")
}
