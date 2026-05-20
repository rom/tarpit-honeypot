//go:build !windows

package sensor

import "golang.org/x/sys/unix"

// diskUsedPercent returns the percentage of the filesystem holding path
// that is in use (0-100), or ok=false if it can't be determined.
func diskUsedPercent(path string) (int, bool) {
	var st unix.Statfs_t
	if err := unix.Statfs(path, &st); err != nil {
		return 0, false
	}
	total := uint64(st.Blocks) * uint64(st.Bsize)
	avail := uint64(st.Bavail) * uint64(st.Bsize)
	if total == 0 {
		return 0, false
	}
	used := total - avail
	return int(used * 100 / total), true
}
