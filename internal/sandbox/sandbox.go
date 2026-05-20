// Package sandbox applies kernel self-confinement to the running
// honeypot: a seccomp-bpf syscall filter and a Landlock filesystem
// restriction. It is defense-in-depth — the sensor is itself a target,
// so even if an attacker finds a parser bug, a seccomp filter that
// denies execve means they can't spawn a shell.
//
// Scope differs by mechanism:
//   - seccomp is applied with TSYNC, so it covers every thread of the
//     process (full-process syscall confinement).
//   - Landlock applies to the calling thread + threads created after it;
//     the Go runtime's pre-existing threads are not retroactively
//     confined (no Landlock TSYNC equivalent), so it is best-effort. Use
//     AppArmor / SELinux / systemd for kernel-enforced full-process
//     filesystem confinement — see docs/hardening.md.
//
// Both mechanisms are Linux-only and best-effort about availability: an
// unsupported kernel (Landlock needs 5.13+) or a denied capability logs
// a warning and the sensor keeps running. Apply must be called AFTER
// privileged setup (binding low ports), data-dir creation, and privilege
// drop — it is a one-way ratchet that only ever removes capability.
package sandbox

import "log/slog"

// Config selects which confinements to apply and the filesystem layout
// Landlock should permit.
type Config struct {
	Seccomp  bool
	Landlock bool
	// DataDir is always granted read+write under Landlock (the sensor's
	// durable state lives here).
	DataDir string
	// ReadPaths are the read-allowed roots. Empty defaults to ["/"]
	// (read everything, write nothing outside the write set).
	ReadPaths []string
	// WritePaths are extra writable roots beyond DataDir.
	WritePaths []string
}

// Enabled reports whether any confinement is requested.
func (c Config) Enabled() bool { return c.Seccomp || c.Landlock }

// Apply installs the requested confinements. Errors are logged, not
// returned fatally: hardening that can't be applied (old kernel, missing
// permission) must not stop the sensor from doing its job. Callers that
// want hard enforcement can check the returned error.
func Apply(cfg Config, log *slog.Logger) error {
	if log == nil {
		log = slog.Default()
	}
	if !cfg.Enabled() {
		return nil
	}
	return apply(cfg, log)
}
