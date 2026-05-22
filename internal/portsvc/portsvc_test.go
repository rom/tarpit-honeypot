package portsvc

import "testing"

func TestName(t *testing.T) {
	cases := map[int]string{22: "ssh", 443: "https", 502: "modbus", 9100: "jetdirect/pjl", 48898: "ads"}
	for p, want := range cases {
		if got := Name(p); got != want {
			t.Errorf("Name(%d)=%q want %q", p, got, want)
		}
	}
	if Name(65000) != "" {
		t.Error("unknown port should return empty")
	}
}

func TestLabel(t *testing.T) {
	if Label(22) != "22 (ssh)" {
		t.Errorf("Label(22)=%q", Label(22))
	}
	if Label(65000) != "65000" {
		t.Errorf("Label(65000)=%q", Label(65000))
	}
	if Label(0) != "" {
		t.Error("Label(0) should be empty")
	}
}
