//go:build !linux

package sandbox

import "log/slog"

// apply is a no-op on non-Linux platforms: seccomp and Landlock are
// Linux kernel features. We log once so the operator knows the
// requested hardening isn't active.
func apply(cfg Config, log *slog.Logger) error {
	log.Warn("sandbox: seccomp/landlock are Linux-only; not applied on this platform")
	return nil
}
