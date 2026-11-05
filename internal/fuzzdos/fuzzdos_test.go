package fuzzdos

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestClassifyPayloadTechniques(t *testing.T) {
	pad := func(s string, n int) []byte { // repeat s up to >= n bytes
		var b strings.Builder
		for b.Len() < n {
			b.WriteString(s)
		}
		return []byte(b.String())
	}
	cases := []struct {
		name    string
		payload []byte
		handler string
		want    string // expected technique ("" = not fuzzing)
	}{
		{"buffer-overflow", bytes.Repeat([]byte("A"), 1000), "http", "buffer-overflow"},
		{"null-flood", append(bytes.Repeat([]byte{0}, 600), []byte("AAAA")...), "ftp", "null-flood"},
		{"format-string", pad("%x.", 90), "http", "format-string"},
		{"oversize-text", pad("abcdefghijklmnop", 20000), "http", "oversize"},
		{"high-entropy", func() []byte { // 0..255 cycled = ~8 bits/byte entropy
			b := make([]byte, 512)
			for i := range b {
				b[i] = byte(i)
			}
			return b
		}(), "http", "high-entropy"},
		{"binary-garbage", bytes.Repeat([]byte{0x01, 0x02}, 64), "http", "binary-garbage"},
		// Negatives:
		{"benign-http", []byte("GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n"), "http", ""},
		{"empty", nil, "http", ""},
		{"binary-proto-high-entropy-ok", func() []byte { // same 0..255 on a binary handler
			b := make([]byte, 512)
			for i := range b {
				b[i] = byte(i)
			}
			return b
		}(), "modbus", ""},
	}
	for _, tc := range cases {
		v := ClassifyPayload(tc.payload, tc.handler)
		if v.Technique != tc.want {
			t.Errorf("%s: Technique = %q; want %q (entropy=%.2f printable=%.2f size=%d)", tc.name, v.Technique, tc.want, v.Entropy, v.Printable, v.Size)
		}
		if v.Fuzzing != (tc.want != "") {
			t.Errorf("%s: Fuzzing = %v; want %v", tc.name, v.Fuzzing, tc.want != "")
		}
	}
}

// Entropy is computed lazily, but a fuzzing verdict must still carry the real
// value because the sensor reports it as payload_entropy meta. (The all-same
// buffer-overflow case legitimately has entropy 0 and is excluded.)
func TestClassifyPayloadEntropyPopulatedForFuzzing(t *testing.T) {
	hi := make([]byte, 512)
	for i := range hi {
		hi[i] = byte(i)
	}
	v := ClassifyPayload(hi, "http")
	if v.Technique != "high-entropy" {
		t.Fatalf("technique = %q; want high-entropy", v.Technique)
	}
	if v.Entropy < highEntropyText {
		t.Errorf("high-entropy verdict carries Entropy %.2f; want >= %.2f (lazy compute did not populate it)", v.Entropy, highEntropyText)
	}
}

func fuzzObs(ip string, port int, tm time.Time, tech string) Observation {
	return Observation{SourceIP: ip, DestPort: port, Time: tm, Fuzz: Verdict{Fuzzing: true, Technique: tech}}
}

func TestTrackerConnectionFlood(t *testing.T) {
	tr := NewTracker(time.Minute)
	base := time.Unix(1_700_000_000, 0)
	var last *Result
	for i := 0; i < connFloodThreshold; i++ {
		// Spread across many ports so app-flood doesn't trip first.
		r := tr.Observe(Observation{SourceIP: "1.1.1.1", DestPort: 1000 + i, Time: base.Add(time.Duration(i) * time.Millisecond)})
		if r != nil {
			last = r
		}
	}
	if last == nil || !last.DoS || last.DoSType != "connection-flood" {
		t.Fatalf("expected connection-flood; got %+v", last)
	}
	if last.Confidence < 50 {
		t.Errorf("confidence = %d; want >= 50", last.Confidence)
	}
}

func TestTrackerAppFlood(t *testing.T) {
	tr := NewTracker(time.Minute)
	base := time.Unix(1_700_000_000, 0)
	var last *Result
	for i := 0; i < appFloodThreshold; i++ {
		r := tr.Observe(Observation{SourceIP: "2.2.2.2", DestPort: 80, Time: base.Add(time.Duration(i) * time.Millisecond)})
		if r != nil {
			last = r
		}
	}
	if last == nil || last.DoSType != "app-flood" {
		t.Fatalf("expected app-flood; got %+v", last)
	}
}

func TestTrackerVolumetric(t *testing.T) {
	tr := NewTracker(time.Minute)
	base := time.Unix(1_700_000_000, 0)
	var last *Result
	for i := 0; i < 10; i++ {
		r := tr.Observe(Observation{SourceIP: "3.3.3.3", DestPort: 443, Time: base.Add(time.Duration(i) * time.Second), Bytes: 1 << 20})
		if r != nil {
			last = r
		}
	}
	if last == nil || last.DoSType != "volumetric" {
		t.Fatalf("expected volumetric; got %+v", last)
	}
}

func TestTrackerFuzzCampaignAndMalformedFlood(t *testing.T) {
	tr := NewTracker(time.Minute)
	base := time.Unix(1_700_000_000, 0)
	var sawFuzz, sawMalformedFlood bool
	var technique string
	for i := 0; i < malformedFlood; i++ {
		r := tr.Observe(fuzzObs("4.4.4.4", 1000+i, base.Add(time.Duration(i)*time.Millisecond), "buffer-overflow"))
		if r == nil {
			continue
		}
		if r.Fuzzing {
			sawFuzz = true
			technique = r.Technique
		}
		if r.DoS && r.DoSType == "malformed-flood" {
			sawMalformedFlood = true
		}
	}
	if !sawFuzz || technique != "buffer-overflow" {
		t.Errorf("expected a fuzzing campaign with buffer-overflow technique (saw=%v tech=%q)", sawFuzz, technique)
	}
	if !sawMalformedFlood {
		t.Errorf("expected a malformed-flood DoS classification")
	}
}

func TestTrackerSlowloris(t *testing.T) {
	tr := NewTracker(time.Minute)
	base := time.Unix(1_700_000_000, 0)
	var last *Result
	// Held-open partial connections to port 80 — but kept under the
	// app-flood threshold so the slowloris label is what fires.
	for i := 0; i < slowlorisThreshold; i++ {
		r := tr.Observe(Observation{SourceIP: "6.6.6.6", DestPort: 80, Time: base.Add(time.Duration(i) * time.Second), Slow: true})
		if r != nil {
			last = r
		}
	}
	if last == nil || !last.DoS || last.DoSType != "slowloris" {
		t.Fatalf("expected slowloris; got %+v", last)
	}
	if last.Confidence < 50 {
		t.Errorf("confidence = %d; want >= 50", last.Confidence)
	}
}

func TestTrackerBenignNoFire(t *testing.T) {
	tr := NewTracker(time.Minute)
	base := time.Unix(1_700_000_000, 0)
	for i := 0; i < 10; i++ {
		if r := tr.Observe(Observation{SourceIP: "5.5.5.5", DestPort: 22, Time: base.Add(time.Duration(i) * time.Second), Bytes: 1024}); r != nil {
			t.Fatalf("benign traffic should not classify: %+v", r)
		}
	}
}

func TestTrackerIgnoresEmptySource(t *testing.T) {
	tr := NewTracker(time.Minute)
	if r := tr.Observe(Observation{SourceIP: "", DestPort: 80}); r != nil {
		t.Error("empty source must be ignored")
	}
}
