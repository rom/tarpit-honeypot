package toolfp

import "testing"

func TestConfidenceLabel(t *testing.T) {
	cases := map[int]string{
		0:          "",
		-5:         "",
		10:         "low",
		ConfLow:    "low",
		54:         "low",
		55:         "medium",
		ConfMedium: "medium",
		79:         "medium",
		80:         "high",
		ConfHigh:   "high",
		100:        "high",
	}
	for c, want := range cases {
		if got := ConfidenceLabel(c); got != want {
			t.Errorf("ConfidenceLabel(%d) = %q; want %q", c, got, want)
		}
	}
}

func TestIdentifyHTTPConfidence(t *testing.T) {
	// A UA tool string is a self-identification → high.
	if v := IdentifyHTTP(HTTPSignals{UserAgent: "sqlmap/1.7", Path: "/"}); v.Confidence != ConfHigh {
		t.Errorf("UA tool match: confidence=%d want %d (%+v)", v.Confidence, ConfHigh, v)
	}
	// Tool inferred from a tool-specific path with no UA → medium.
	v := IdentifyHTTP(HTTPSignals{UserAgent: "", Path: "/nmaplowercheck"})
	if !contains(v.Tools, "nmap") {
		t.Fatalf("path match did not identify nmap: %+v", v)
	}
	if v.Confidence != ConfMedium {
		t.Errorf("path-only match: confidence=%d want %d (%+v)", v.Confidence, ConfMedium, v)
	}
	// Browser UA but missing Accept-* headers → low, no tool.
	v = IdentifyHTTP(HTTPSignals{UserAgent: "Mozilla/5.0 Chrome/120 Safari/537", Path: "/"})
	if v.Confidence != ConfLow {
		t.Errorf("weak-heuristic automation: confidence=%d want %d (%+v)", v.Confidence, ConfLow, v)
	}
	// A genuine browser is not automation and carries no confidence score.
	v = IdentifyHTTP(HTTPSignals{
		UserAgent:  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36",
		Path:       "/",
		HeaderKeys: []string{"accept", "accept-language", "accept-encoding"},
	})
	if v.Confidence != 0 {
		t.Errorf("browser: confidence=%d want 0 (%+v)", v.Confidence, v)
	}
}
