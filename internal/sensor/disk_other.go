//go:build windows

package sensor

// diskUsedPercent is unavailable on this platform; health checks skip the
// disk signal.
func diskUsedPercent(string) (int, bool) { return 0, false }
