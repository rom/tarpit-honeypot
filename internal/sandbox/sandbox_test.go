package sandbox

import "testing"

func TestConfigEnabled(t *testing.T) {
	if (Config{}).Enabled() {
		t.Error("zero Config should be disabled")
	}
	if !(Config{Seccomp: true}).Enabled() {
		t.Error("seccomp should count as enabled")
	}
	if !(Config{Landlock: true}).Enabled() {
		t.Error("landlock should count as enabled")
	}
}

func TestApplyDisabledIsNoop(t *testing.T) {
	if err := Apply(Config{}, nil); err != nil {
		t.Errorf("disabled Apply should be a no-op; got %v", err)
	}
}
