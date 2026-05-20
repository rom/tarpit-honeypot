package filter

import "testing"

func TestAllowlist(t *testing.T) {
	a, err := NewAllowlist([]string{"10.0.0.0/8", "192.168.1.5", "::1"})
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]bool{
		"10.0.0.1":       true,
		"10.255.255.255": true,
		"192.168.1.5":    true,
		"192.168.1.6":    false,
		"172.16.0.1":     false,
		"::1":            true,
		"::2":            false,
		"not-an-ip":      false,
	}
	for ip, want := range cases {
		if got := a.Contains(ip); got != want {
			t.Errorf("Contains(%q) = %v, want %v", ip, got, want)
		}
	}
}

func TestAllowlistRejectsGarbage(t *testing.T) {
	_, err := NewAllowlist([]string{"not-an-ip"})
	if err == nil {
		t.Errorf("expected error on garbage entry")
	}
}

func TestNilAllowlist(t *testing.T) {
	var a *Allowlist
	if a.Contains("1.2.3.4") {
		t.Error("nil allowlist should not contain anything")
	}
}
