package config

import "testing"

func TestPayloadsUploadCapBytes(t *testing.T) {
	if got := (Payloads{}).UploadCapBytes(); got != 1<<20 {
		t.Errorf("default upload cap = %d, want 1 MiB", got)
	}
	if got := (Payloads{MaxUploadKB: 8192}).UploadCapBytes(); got != 8192<<10 {
		t.Errorf("configured upload cap = %d, want 8 MiB", got)
	}
}
