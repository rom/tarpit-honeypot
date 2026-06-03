package privdrop

import (
	"os"
	"testing"
)

func TestDropNoOp(t *testing.T) {
	// Empty user + group is always a no-op on every platform.
	if err := Drop("", ""); err != nil {
		t.Errorf("Drop(\"\",\"\") = %v, want nil", err)
	}
}

func TestDropIgnoredWhenNotRoot(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root; the not-root ignore path doesn't apply")
	}
	// A non-root process can't change uid/gid, so Drop logs a warning and
	// returns nil rather than erroring — even for a user that doesn't exist,
	// because it bails before the lookup.
	if err := Drop("definitely-not-a-real-user-xyz", ""); err != nil {
		t.Errorf("Drop(...) when non-root = %v, want nil (ignored)", err)
	}
}
