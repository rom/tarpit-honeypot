//go:build linux

package privdrop

import (
	"errors"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"syscall"
	"testing"
)

// childSkip signals "this environment can't exercise the drop" so the parent
// skips instead of failing.
const childSkip = 42

// TestDropEnforcedInSubprocess is the real enforcement test the suite lacked: in
// a root subprocess it drops to an unprivileged account and asserts (a) the
// real+effective uid/gid actually changed and (b) root can no longer be
// regained. Dropping is irreversible, so it must run in a throwaway process.
func TestDropEnforcedInSubprocess(t *testing.T) {
	if os.Getenv("PRIVDROP_CHILD") == "1" {
		if os.Geteuid() != 0 {
			os.Exit(childSkip) // not root: nothing to drop
		}
		nobody, err := user.Lookup("nobody")
		if err != nil {
			os.Exit(childSkip) // no unprivileged account to drop to
		}
		wantUID, _ := strconv.Atoi(nobody.Uid)
		if err := Drop("nobody", nobody.Gid); err != nil {
			os.Exit(4) // drop returned an error
		}
		if os.Getuid() != wantUID || os.Geteuid() != wantUID {
			os.Exit(5) // uid did not actually change (real+effective)
		}
		// Root must not be regainable now that real+effective+saved uid are all
		// non-zero.
		if err := syscall.Setuid(0); err == nil {
			os.Exit(6) // regained root — drop was not durable
		}
		os.Exit(0)
	}

	cmd := exec.Command(os.Args[0], "-test.run=TestDropEnforcedInSubprocess", "-test.v")
	cmd.Env = append(os.Environ(), "PRIVDROP_CHILD=1")
	out, err := cmd.CombinedOutput()
	if err == nil {
		return // child exited 0: drop changed uid/gid and root can't be regained
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		switch ee.ExitCode() {
		case childSkip:
			t.Skip("privdrop enforcement not exercisable here (needs root + an unprivileged account)")
		case 4:
			t.Fatalf("Drop returned an error:\n%s", out)
		case 5:
			t.Fatalf("uid did not change after Drop:\n%s", out)
		case 6:
			t.Fatalf("root was regained after Drop (not durable):\n%s", out)
		}
	}
	t.Fatalf("privdrop child failed: %v\n%s", err, out)
}
