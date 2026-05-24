package testharness

// Fuzz targets for the harness. "Dumb" targets feed arbitrary scalars/selectors
// and assert the parsers never panic; "smart" targets seed with structured
// inputs and assert the reproducibility / bound invariants the harness relies
// on (a recorded seed must replay identical fuzz inputs).
//
//	go test ./internal/testharness -run x -fuzz FuzzMutateSmart -fuzztime 30s

import (
	"reflect"
	"testing"

	"gopkg.in/yaml.v3"
)

// --- dumb -------------------------------------------------------------------

// FuzzDurationUnmarshal: Duration must parse any YAML scalar without panicking,
// and any value it accepts must survive a marshal → unmarshal round-trip.
func FuzzDurationUnmarshal(f *testing.F) {
	for _, s := range []string{"30m", "0", "1.5", "2h45m", "500ms", "bogus", "30x", "", "null"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		var d Duration
		if err := yaml.Unmarshal([]byte(s), &d); err != nil {
			return // a rejected scalar is a fine outcome
		}
		b, err := yaml.Marshal(d)
		if err != nil {
			t.Fatalf("marshal of accepted %q failed: %v", s, err)
		}
		var d2 Duration
		if err := yaml.Unmarshal(b, &d2); err != nil || d2.D() != d.D() {
			t.Fatalf("round-trip of %q: %s != %s (%v)", s, d2, d, err)
		}
	})
}

// FuzzSelectMatch: Select must never panic on an arbitrary selector or category
// string, and what it returns is always a subset of the built case set.
func FuzzSelectMatch(f *testing.F) {
	cfg := &Config{Mode: "network", Host: "127.0.0.1", Endpoints: []Endpoint{
		{Label: "ssh", Proto: "tcp", Port: 22, Handler: "ssh"},
		{Label: "http", Proto: "tcp", Port: 80, Handler: "http"},
	}}
	cfg.ApplyDefaults()
	cases := Build(cfg)
	for _, s := range []string{"fuzz-*", "unit/port-open/", "*/ssh", "scan", "emulate/http", ""} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, sel string) {
		got := Select(cases, []string{sel}, nil)
		if len(got) > len(cases) {
			t.Fatalf("Select returned more cases than exist: %d > %d", len(got), len(cases))
		}
		_ = Select(cases, nil, []string{sel}) // exercise the category axis too
	})
}

// --- smart ------------------------------------------------------------------

// FuzzMutateSmart: the smart-fuzz mutator is deterministic for a given seed+id
// and never grows an input past the base plus its bounded extension.
func FuzzMutateSmart(f *testing.F) {
	f.Add(int64(1), []byte("SSH-2.0-probe"))
	f.Add(int64(8024599), []byte{0xff, 0xfd, 0x01, 0x00})
	f.Add(int64(0), []byte{})
	f.Fuzz(func(t *testing.T, seed int64, base []byte) {
		a := mutate(caseRand(seed, "f"), base)
		b := mutate(caseRand(seed, "f"), base)
		if !reflect.DeepEqual(a, b) {
			t.Fatalf("mutate non-deterministic for seed=%d base=%x", seed, base)
		}
		if len(a) > len(base)+512 {
			t.Fatalf("mutate grew %d -> %d (beyond the +512 bound)", len(base), len(a))
		}
	})
}

// FuzzRandBytesStable: the replay-by-seed guarantee — the same seed + case id
// reproduces an identical fuzz input — and the input respects its size bound.
func FuzzRandBytesStable(f *testing.F) {
	f.Add(int64(1), "fuzz-dumb/ssh")
	f.Add(int64(42), "fuzz-dumb/http")
	f.Add(int64(-7), "")
	f.Fuzz(func(t *testing.T, seed int64, id string) {
		a := randBytes(caseRand(seed, id))
		b := randBytes(caseRand(seed, id))
		if !reflect.DeepEqual(a, b) {
			t.Fatalf("randBytes not reproducible for seed=%d id=%q", seed, id)
		}
		if len(a) > 16384 {
			t.Fatalf("randBytes len %d exceeds the 16384 bound", len(a))
		}
	})
}
