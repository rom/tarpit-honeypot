//go:build linux

package privdrop

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/user"
	"strconv"
	"syscall"
)

// Drop switches the running process to the given user/group. Either
// argument may be empty: if both are empty, Drop is a no-op. The user
// argument may be a numeric uid or a username; the group similarly.
//
// On Linux, Go's syscall.Setuid/Setgid (since 1.16) use AllThreadsSyscall,
// so the change is visible across the whole runtime. We refuse to drop to
// uid 0 — that's almost certainly a misconfiguration.
func Drop(usr, grp string) error {
	if usr == "" && grp == "" {
		return nil
	}
	if os.Geteuid() != 0 {
		slog.Warn("privdrop: not running as root; drop_user/drop_group ignored")
		return nil
	}

	var uid, gid int = -1, -1
	if usr != "" {
		u, err := lookupUser(usr)
		if err != nil {
			return err
		}
		id, err := strconv.Atoi(u.Uid)
		if err != nil {
			return fmt.Errorf("privdrop: parse uid %q: %w", u.Uid, err)
		}
		if id == 0 {
			return errors.New("privdrop: refusing to drop to uid 0")
		}
		uid = id
		// Default to the user's primary group if no explicit group given.
		if grp == "" {
			if pgid, err := strconv.Atoi(u.Gid); err == nil {
				gid = pgid
			}
		}
	}
	if grp != "" {
		g, err := lookupGroup(grp)
		if err != nil {
			return err
		}
		id, err := strconv.Atoi(g.Gid)
		if err != nil {
			return fmt.Errorf("privdrop: parse gid %q: %w", g.Gid, err)
		}
		gid = id
	}

	// Set supplementary groups before setting uid (which removes privilege).
	if gid >= 0 {
		if err := syscall.Setgroups([]int{gid}); err != nil {
			slog.Warn("privdrop: setgroups failed", "err", err)
		}
		if err := syscall.Setgid(gid); err != nil {
			return fmt.Errorf("privdrop: setgid(%d): %w", gid, err)
		}
	}
	if uid >= 0 {
		if err := syscall.Setuid(uid); err != nil {
			return fmt.Errorf("privdrop: setuid(%d): %w", uid, err)
		}
	}
	slog.Info("privdrop done", "uid", uid, "gid", gid)
	return nil
}

func lookupUser(s string) (*user.User, error) {
	if u, err := user.LookupId(s); err == nil {
		return u, nil
	}
	u, err := user.Lookup(s)
	if err != nil {
		return nil, fmt.Errorf("privdrop: lookup user %q: %w", s, err)
	}
	return u, nil
}

func lookupGroup(s string) (*user.Group, error) {
	if g, err := user.LookupGroupId(s); err == nil {
		return g, nil
	}
	g, err := user.LookupGroup(s)
	if err != nil {
		return nil, fmt.Errorf("privdrop: lookup group %q: %w", s, err)
	}
	return g, nil
}
