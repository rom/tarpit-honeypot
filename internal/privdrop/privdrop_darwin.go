//go:build darwin

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

// Drop switches the running process to the given user/group on macOS.
// Either argument may be empty: if both are empty, Drop is a no-op.
//
// macOS differs from Linux in two important ways:
//
//   1. There is no setresuid — only setuid / setreuid. We use Setuid
//      which on darwin maps to pthread_setugid_np / setuid(2) and
//      affects the whole process (Go pre-empts the thread-locked
//      goroutine and re-issues on the new identity). After Setuid the
//      saved-uid is also dropped to the target, so a later regain of
//      root via setuid(0) won't work — same security posture as
//      Linux's setresuid path.
//
//   2. macOS doesn't support the same fine-grained capability model
//      as Linux (no CAP_NET_BIND_SERVICE). The operator typically
//      binds privileged ports as root and then drops; alternatively,
//      pf rules can redirect low ports to a high port the unpriv
//      user opens. We don't enforce that here — the operator's
//      systemd / launchd config decides.
//
// We refuse to drop to uid 0; that's almost always a misconfiguration.
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
		u, err := lookupUserDarwin(usr)
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
		if grp == "" {
			if pgid, err := strconv.Atoi(u.Gid); err == nil {
				gid = pgid
			}
		}
	}
	if grp != "" {
		g, err := lookupGroupDarwin(grp)
		if err != nil {
			return err
		}
		id, err := strconv.Atoi(g.Gid)
		if err != nil {
			return fmt.Errorf("privdrop: parse gid %q: %w", g.Gid, err)
		}
		gid = id
	}

	// Order matters: group first (still privileged) then user (drops
	// privilege). Setgroups must come before Setgid on macOS too;
	// otherwise the unprivileged user retains the root supplementary
	// group set.
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
	slog.Info("privdrop done", "uid", uid, "gid", gid, "platform", "darwin")
	return nil
}

func lookupUserDarwin(s string) (*user.User, error) {
	if u, err := user.LookupId(s); err == nil {
		return u, nil
	}
	u, err := user.Lookup(s)
	if err != nil {
		return nil, fmt.Errorf("privdrop: lookup user %q: %w", s, err)
	}
	return u, nil
}

func lookupGroupDarwin(s string) (*user.Group, error) {
	if g, err := user.LookupGroupId(s); err == nil {
		return g, nil
	}
	g, err := user.LookupGroup(s)
	if err != nil {
		return nil, fmt.Errorf("privdrop: lookup group %q: %w", s, err)
	}
	return g, nil
}
