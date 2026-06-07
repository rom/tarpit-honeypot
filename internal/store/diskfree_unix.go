//go:build unix

package store

import "syscall"

// freeDiskBytes returns the bytes available to an unprivileged process on the
// filesystem backing dir, and ok=false if it can't be determined. Used to warn
// before / diagnose after SQLite fails to grow the WAL/-shm on a full disk.
func freeDiskBytes(dir string) (int64, bool) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err != nil {
		return 0, false
	}
	// Bavail is the count of blocks available to non-root; Bsize is the block
	// size. Cast both to uint64 so the expression compiles across Unix variants
	// (Bsize is int64 on Linux, uint32 on Darwin) before narrowing to int64.
	free := uint64(st.Bavail) * uint64(st.Bsize)
	return int64(free), true
}
