package handler

import (
	"testing"
)

// FuzzLDAPParseMessage feeds arbitrary bytes through the LDAP BER decoder
// to make sure malformed input never panics. We hit this path in v0.9
// with a real off-by-N bug in parseBERInteger — having a permanent fuzz
// target prevents the regression.
//
// Run for longer in CI:
//   go test -run='^$' -fuzz=FuzzLDAPParseMessage -fuzztime=60s ./internal/listener/handler
func FuzzLDAPParseMessage(f *testing.F) {
	// Seed corpus: the bind request we know is valid.
	f.Add(buildLDAPBindFixture("admin", "hunter2"))
	// And the SMB2-shaped junk we already feed the SMB parser, which
	// should be rejected here.
	f.Add([]byte{0xFE, 'S', 'M', 'B', 0x40, 0, 0, 0})
	// And the empty buffer.
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		// Defer recover so any panic counts as a fuzz failure with
		// the test framework's own reporting.
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("parseLDAPMessage panicked: %v", r)
			}
		}()
		mid, op, body, ok := parseLDAPMessage(data)
		if !ok {
			return // legitimately malformed, fine
		}
		if op == 0x60 {
			// BindRequest — exercise the bind decoder too.
			_, _, _, _ = parseBindRequest(body)
		}
		_ = mid
	})
}

// buildLDAPBindFixture mirrors the production wire format the unit test
// in ics3_test.go builds, so the seed corpus matches what real
// scanners send.
func buildLDAPBindFixture(user, pass string) []byte {
	dn := []byte(user)
	pw := []byte(pass)
	bindOp := []byte{0x02, 0x01, 0x03}
	bindOp = append(bindOp, 0x04, byte(len(dn)))
	bindOp = append(bindOp, dn...)
	bindOp = append(bindOp, 0x80, byte(len(pw)))
	bindOp = append(bindOp, pw...)
	msg := []byte{0x02, 0x01, 0x01, 0x60, byte(len(bindOp))}
	msg = append(msg, bindOp...)
	return append([]byte{0x30, byte(len(msg))}, msg...)
}
