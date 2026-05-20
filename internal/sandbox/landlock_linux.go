//go:build linux

package sandbox

import (
	"errors"
	"fmt"
	"unsafe"

	"golang.org/x/sys/unix"
)

// landlockCreateRulesetVersion is the LANDLOCK_CREATE_RULESET_VERSION
// flag — passed with a NULL attr to query the kernel's supported ABI.
const landlockCreateRulesetVersion = 1

// errLandlockUnsupported means the kernel lacks Landlock (pre-5.13 or
// compiled out). Treated as best-effort by the caller.
var errLandlockUnsupported = errors.New("landlock: unsupported by kernel")

// applyLandlock confines the process's filesystem access: read+traverse
// allowed under ReadPaths (default "/"), and write/create/remove allowed
// only under DataDir + WritePaths. Everything else becomes read-only, so
// an attacker who lands code execution can't drop persistence, tamper
// with system binaries, or write outside the honeypot's own state dir.
func applyLandlock(cfg Config) error {
	abi := landlockABI()
	if abi < 1 {
		return errLandlockUnsupported
	}
	fsAccess := handledAccessFS(abi)

	attr := unix.LandlockRulesetAttr{Access_fs: fsAccess}
	rulesetFD, _, errno := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET,
		uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr), 0)
	if errno != 0 {
		return fmt.Errorf("landlock: create_ruleset: %w", errno)
	}
	defer unix.Close(int(rulesetFD))

	// Read-only roots (default: the whole filesystem readable).
	readPaths := cfg.ReadPaths
	if len(readPaths) == 0 {
		readPaths = []string{"/"}
	}
	const readMask = unix.LANDLOCK_ACCESS_FS_READ_FILE | unix.LANDLOCK_ACCESS_FS_READ_DIR
	for _, p := range readPaths {
		if _, err := addPathRule(int(rulesetFD), p, readMask&fsAccess); err != nil {
			return err
		}
	}

	// Writable roots: data_dir (must exist) + operator extras.
	writePaths := append([]string{cfg.DataDir}, cfg.WritePaths...)
	for i, p := range writePaths {
		if p == "" {
			continue
		}
		added, err := addPathRule(int(rulesetFD), p, fsAccess)
		if err != nil {
			return err
		}
		if !added && i == 0 {
			return fmt.Errorf("landlock: data_dir %q not found", p)
		}
	}

	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("landlock: PR_SET_NO_NEW_PRIVS: %w", err)
	}
	if _, _, errno := unix.Syscall(unix.SYS_LANDLOCK_RESTRICT_SELF, rulesetFD, 0, 0); errno != 0 {
		return fmt.Errorf("landlock: restrict_self: %w", errno)
	}
	return nil
}

// landlockABI returns the kernel's supported Landlock ABI version, or
// <=0 when Landlock is unavailable.
func landlockABI() int {
	r1, _, errno := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, 0, 0, landlockCreateRulesetVersion)
	if errno != 0 {
		return -1
	}
	return int(r1)
}

// handledAccessFS returns the full set of filesystem access rights for
// the kernel's ABI version. Bits the running kernel doesn't know would
// make create_ruleset fail, so we add later-ABI rights conditionally.
func handledAccessFS(abi int) uint64 {
	a := uint64(unix.LANDLOCK_ACCESS_FS_EXECUTE |
		unix.LANDLOCK_ACCESS_FS_WRITE_FILE |
		unix.LANDLOCK_ACCESS_FS_READ_FILE |
		unix.LANDLOCK_ACCESS_FS_READ_DIR |
		unix.LANDLOCK_ACCESS_FS_REMOVE_DIR |
		unix.LANDLOCK_ACCESS_FS_REMOVE_FILE |
		unix.LANDLOCK_ACCESS_FS_MAKE_CHAR |
		unix.LANDLOCK_ACCESS_FS_MAKE_DIR |
		unix.LANDLOCK_ACCESS_FS_MAKE_REG |
		unix.LANDLOCK_ACCESS_FS_MAKE_SOCK |
		unix.LANDLOCK_ACCESS_FS_MAKE_FIFO |
		unix.LANDLOCK_ACCESS_FS_MAKE_BLOCK |
		unix.LANDLOCK_ACCESS_FS_MAKE_SYM)
	if abi >= 2 {
		a |= unix.LANDLOCK_ACCESS_FS_REFER
	}
	if abi >= 3 {
		a |= unix.LANDLOCK_ACCESS_FS_TRUNCATE
	}
	if abi >= 5 {
		a |= unix.LANDLOCK_ACCESS_FS_IOCTL_DEV
	}
	return a
}

// addPathRule grants access under path. Returns (false, nil) when the
// path doesn't exist (skipped); a non-ENOENT open error is fatal.
func addPathRule(rulesetFD int, path string, access uint64) (bool, error) {
	fd, err := unix.Open(path, unix.O_PATH|unix.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return false, nil
		}
		return false, fmt.Errorf("landlock: open %q: %w", path, err)
	}
	defer unix.Close(fd)
	rule := unix.LandlockPathBeneathAttr{Allowed_access: access, Parent_fd: int32(fd)}
	if _, _, errno := unix.Syscall6(unix.SYS_LANDLOCK_ADD_RULE,
		uintptr(rulesetFD), uintptr(unix.LANDLOCK_RULE_PATH_BENEATH),
		uintptr(unsafe.Pointer(&rule)), 0, 0, 0); errno != 0 {
		return false, fmt.Errorf("landlock: add_rule %q: %w", path, errno)
	}
	return true, nil
}
