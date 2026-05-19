//go:build !linux

package privdrop

import "log/slog"

// Drop is a no-op on non-linux platforms. The CLI logs a warning when
// drop_user/drop_group are set but unenforceable.
func Drop(usr, grp string) error {
	if usr != "" || grp != "" {
		slog.Warn("privdrop: drop_user/drop_group are ignored on this platform")
	}
	return nil
}
