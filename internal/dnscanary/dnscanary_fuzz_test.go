package dnscanary

import (
	"testing"
)

// FuzzParseQuery feeds arbitrary bytes through the DNS query parser. The
// parser has length-prefixed labels with a hard "no pointers" rule —
// pointer compression and other oddities should all be safely rejected
// rather than crashing.
//
// Run for longer in CI:
//
//	go test -run='^$' -fuzz=FuzzParseQuery -fuzztime=60s ./internal/dnscanary
func FuzzParseQuery(f *testing.F) {
	// Seed corpus: a known-good query, and a few intentionally broken
	// ones that the parser must reject.
	f.Add(buildQuery(&testing.T{}, "example.com", 1))
	f.Add(buildQuery(&testing.T{}, "single", 16))
	f.Add([]byte{})                                                           // too short
	f.Add([]byte{0, 0, 0, 0})                                                 // header-only
	f.Add([]byte{0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0xC0, 0x0C, 0, 1, 0, 1}) // pointer-prefixed name

	f.Fuzz(func(t *testing.T, data []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("parseQuery panicked: %v", r)
			}
		}()
		_, _, _ = parseQuery(data)
		// also exercise buildNXDOMAIN which mutates the input
		_ = buildNXDOMAIN(append([]byte(nil), data...))
		_ = buildA(append([]byte(nil), data...), "10.0.0.1")
	})
}
