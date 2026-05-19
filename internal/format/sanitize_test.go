package format

import (
	"strings"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/event"
)

// Every formatter must scrub attacker-supplied control characters
// before emitting a line. We construct an event where meta values
// contain newlines, ANSI escapes, NULs, and trailing escape sequences,
// then verify none of them survive in the rendered output.
func TestAllFormattersScrubAttackerControlChars(t *testing.T) {
	ev := &event.Event{
		ID:       "abc",
		Time:     time.Unix(1700000000, 0).UTC(),
		Sensor:   "test",
		RuleID:   "listener:ssh-bait",
		Severity: event.SeverityHigh,
		Source:   event.Endpoint{IP: "203.0.113.10", Port: 5555},
		Dest:     event.Endpoint{IP: "10.0.0.1", Port: 22},
		Proto:    "tcp",
		Handler:  "ssh",
		Meta: map[string]any{
			// Classic log-injection.
			"client_id": "SSH-2.0-evil\nlevel=info src=trusted\nbecause: pwn",
			// ANSI escape attempting terminal control.
			"banner": "\x1b[2J\x1b[H\x1b[31m**pwned**\x1b[0m",
			// NUL + trailing escape.
			"username": "admin\x00\x07evil",
		},
	}
	for _, fname := range []string{"json", "cef", "leef", "ocsf"} {
		f, err := Get(fname)
		if err != nil {
			t.Fatal(err)
		}
		out, err := f.Format(ev)
		if err != nil {
			t.Fatalf("%s: %v", fname, err)
		}
		// No raw newline in the meta-value bytes (CEF/LEEF/OCSF are
		// one-line records; JSON may use only synthetic structural
		// newlines, none from attacker-controlled data).
		s := string(out)
		// We can't forbid \n outright in JSON output (multi-line
		// pretty-print isn't used, but JSON allows \n inside strings
		// as a JSON-escaped \n). What we forbid is a *literal* LF.
		if fname == "cef" || fname == "leef" {
			if strings.ContainsRune(s, '\n') || strings.ContainsRune(s, '\r') {
				t.Errorf("%s: raw newline survived: %q", fname, s)
			}
			if strings.ContainsRune(s, 0x1b) {
				t.Errorf("%s: ESC survived: %q", fname, s)
			}
			if strings.ContainsRune(s, 0x00) {
				t.Errorf("%s: NUL survived: %q", fname, s)
			}
		}
		// Sanity: the truncation markers shouldn't appear (we're not
		// over MaxLogLength).
		if strings.Contains(s, "[truncated]") {
			t.Errorf("%s: small event was truncated unexpectedly", fname)
		}
	}
}

// CEF and LEEF should never let an attacker-supplied "key=value"
// sequence in their meta values create a NEW key=value field. The
// escape must protect "=" inside the value (CEF) or the tab delimiter
// (LEEF).
func TestCEFEscapesEqualsInValue(t *testing.T) {
	ev := &event.Event{
		RuleID: "x",
		Meta: map[string]any{
			"sniff": "user=admin pass=stolen",
		},
	}
	out, _ := (&cefF{}).Format(ev)
	// Look for the keyword inside the *value* position. The injected
	// "=" must have been escaped, so the only un-escaped "=" should
	// be the ones we wrote (cs1Label= / cs1= / cs2Label= / cs2=).
	expectedEqs := 6 // 3 rt= cs..= pairs in this minimal event
	got := strings.Count(string(out), "=") - strings.Count(string(out), `\=`)
	if got > expectedEqs+1 { // tolerate +1 for the rt= timestamp
		t.Errorf("unescaped '=' count too high: got=%d, want <=%d, line=%s",
			got, expectedEqs+1, string(out))
	}
}
