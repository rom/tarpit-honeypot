//go:build linux

package sandbox

import "log/slog"

// apply installs Landlock first (it needs to open directory fds, which
// nothing here blocks) and then the seccomp filter. Each step is
// best-effort and logged; a failure in one does not skip the other.
func apply(cfg Config, log *slog.Logger) error {
	var firstErr error
	if cfg.Landlock {
		if err := applyLandlock(cfg); err != nil {
			log.Warn("sandbox: landlock not applied", "err", err)
			if firstErr == nil {
				firstErr = err
			}
		} else {
			log.Info("sandbox: landlock filesystem restriction active", "data_dir", cfg.DataDir)
		}
	}
	if cfg.Seccomp {
		if err := applySeccomp(); err != nil {
			log.Warn("sandbox: seccomp filter not applied", "err", err)
			if firstErr == nil {
				firstErr = err
			}
		} else {
			log.Info("sandbox: seccomp syscall filter active")
		}
	}
	return firstErr
}
