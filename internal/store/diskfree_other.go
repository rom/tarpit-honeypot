//go:build !unix

package store

// freeDiskBytes is a no-op on non-Unix platforms (the sensor's production
// target is Linux); callers treat ok=false as "unknown" and skip the check.
func freeDiskBytes(string) (int64, bool) { return 0, false }
