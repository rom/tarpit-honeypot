package main

import "testing"

func TestParseEndpoints(t *testing.T) {
	eps, err := parseEndpoints([]string{"ssh=tcp:22:ssh", "modbus=udp:502:modbus_udp", "web=tcp:80"})
	if err != nil {
		t.Fatal(err)
	}
	if len(eps) != 3 {
		t.Fatalf("got %d endpoints, want 3", len(eps))
	}
	if eps[0].Label != "ssh" || eps[0].Proto != "tcp" || eps[0].Port != 22 || eps[0].Handler != "ssh" {
		t.Errorf("ep0 = %+v", eps[0])
	}
	if eps[1].Proto != "udp" || eps[1].Port != 502 || eps[1].Handler != "modbus_udp" {
		t.Errorf("ep1 = %+v", eps[1])
	}
	if eps[2].Handler != "" { // handler is optional
		t.Errorf("ep2 handler should be empty, got %q", eps[2].Handler)
	}
}

func TestParseEndpointsErrors(t *testing.T) {
	for _, bad := range []string{"no-equals", "x=tcp", "x=tcp:notaport"} {
		if _, err := parseEndpoints([]string{bad}); err == nil {
			t.Errorf("parseEndpoints(%q) should error", bad)
		}
	}
}

func TestSplitCSV(t *testing.T) {
	got := splitCSV([]string{"a, b ,c", "", "d"})
	want := []string{"a", "b", "c", "d"}
	if len(got) != len(want) {
		t.Fatalf("splitCSV = %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("splitCSV[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestTrunc(t *testing.T) {
	if trunc("hello", 10) != "hello" {
		t.Error("short string must be unchanged")
	}
	got := trunc("hello world", 6)
	if []rune(got)[len([]rune(got))-1] != '…' {
		t.Errorf("trunc should end with ellipsis, got %q", got)
	}
}

func TestParseReports(t *testing.T) {
	r := parseReports([]string{"json=out.json", "text"})
	if len(r) != 2 || r[0].Format != "json" || r[0].Path != "out.json" || r[1].Format != "text" || r[1].Path != "-" {
		t.Errorf("parseReports = %+v", r)
	}
}
