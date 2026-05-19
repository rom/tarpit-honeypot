//go:build !linux && !darwin

package privdrop

import "log/slog"

// Drop is a no-op on platforms without a setuid-shaped privilege
// model (Windows, Plan 9). The CLI logs a warning when
// drop_user/drop_group are set but unenforceable so the operator
// notices a misconfiguration rather than silently keeping root.
func Drop(usr, grp string) error {
	if usr != "" || grp != "" {
		slog.Warn("privdrop: drop_user/drop_group are ignored on this platform")
	}
	return nil
}
