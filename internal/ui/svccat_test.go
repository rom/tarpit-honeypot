package ui

import "testing"

func TestSvcCategory(t *testing.T) {
	cases := map[string]string{
		"modbus": "ot", "bacnet": "ot", "dicom": "ot", "niagara_platform": "ot",
		"agent": "ai", "mcp": "ai", "ollama": "ai", "llm_openai": "ai",
		"ssh": "remote", "rdp": "remote", "vnc": "remote", "telnet": "remote",
		"http": "", "redis": "", "": "",
	}
	for h, want := range cases {
		if got := svcCategory(h); got != want {
			t.Errorf("svcCategory(%q) = %q, want %q", h, got, want)
		}
	}
}
