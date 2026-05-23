//go:build windows

package ui

import "os"

// openNoFollow opens path read-only. Windows lacks O_NOFOLLOW; symlink
// creation requires elevated privilege there and the download paths are
// already validated to stay inside the data dir, so a plain read-only open
// is the best-effort equivalent.
func openNoFollow(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY, 0)
}
