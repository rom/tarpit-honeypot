//go:build !windows

package ui

import (
	"os"
	"syscall"
)

// openNoFollow opens path read-only and refuses to traverse a symlink at
// the final component (O_NOFOLLOW), so a planted symlink can't redirect a
// download outside the data dir.
func openNoFollow(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
}
