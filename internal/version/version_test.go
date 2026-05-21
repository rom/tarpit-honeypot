package version

import "testing"

func TestVersionSet(t *testing.T) {
	if Version == "" || Version == "dev" || Version == "unknown" {
		t.Errorf("Version should be a real default, got %q", Version)
	}
	if Commit == "" || BuildDate == "" {
		t.Error("Commit/BuildDate must have non-empty defaults")
	}
}
