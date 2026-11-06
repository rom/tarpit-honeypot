package format

import (
	"strings"
	"testing"

	"github.com/rom/tarpit-honeypot/internal/event"
)

// TestFormatterNameAndContentType exercises the trivial identity methods on
// every formatter — they're part of the Formatter contract the sinks rely on
// to set the right wire content type.
func TestFormatterNameAndContentType(t *testing.T) {
	want := map[string][2]string{
		"":     {"json", "application/json"},
		"json": {"json", "application/json"},
		"cef":  {"cef", "text/plain; charset=utf-8"},
		"leef": {"leef", "text/plain; charset=utf-8"},
		"ocsf": {"ocsf", "application/json"},
	}
	for name, exp := range want {
		f, err := Get(name)
		if err != nil {
			t.Fatalf("Get(%q): %v", name, err)
		}
		if got := f.Name(); got != exp[0] {
			t.Errorf("Get(%q).Name() = %q; want %q", name, got, exp[0])
		}
		if got := f.ContentType(); got != exp[1] {
			t.Errorf("Get(%q).ContentType() = %q; want %q", name, got, exp[1])
		}
	}
}

// TestCEFNameMapsRulePrefixes covers every rule_id prefix branch of cefName,
// plus the pass-through default.
func TestCEFNameMapsRulePrefixes(t *testing.T) {
	cases := map[string]string{
		"listener:http":                 "Honeypot listener triggered",
		"canary:url:abc":                "URL canary triggered",
		"canary:dns:abc":                "DNS canary triggered",
		"canary:file:secret.docx":       "File canary triggered",
		"correlate:port_scan":           "Port scan detected",
		"correlate:brute_force:ssh":     "Brute-force detected",
		"correlate:slow_scan":           "Slow scan detected",
		"sniffer:arp_scan":              "ARP scan detected",
		"sniffer:arp_reply_unsolicited": "Unsolicited ARP reply",
		"dnscanary:query":               "DNS canary listener event",
		"sensor:reload":                 "Sensor configuration reload",
		"something:else":                "something:else", // default: echo rule id
	}
	for ruleID, want := range cases {
		got := cefName(&event.Event{RuleID: ruleID})
		if got != want {
			t.Errorf("cefName(%q) = %q; want %q", ruleID, got, want)
		}
	}
}

// TestSeverityMappings covers the CEF (0-10) and OCSF (1-6) severity scales for
// every defined severity plus the out-of-range default.
func TestSeverityMappings(t *testing.T) {
	cef := map[event.Severity]int{
		event.SeverityLow:      2,
		event.SeverityMedium:   5,
		event.SeverityHigh:     7,
		event.SeverityCritical: 10,
		event.Severity(0):      0, // default / unset
	}
	for sev, want := range cef {
		if got := cefSeverity(sev); got != want {
			t.Errorf("cefSeverity(%v) = %d; want %d", sev, got, want)
		}
	}
	ocsf := map[event.Severity]int{
		event.SeverityLow:      2,
		event.SeverityMedium:   3,
		event.SeverityHigh:     4,
		event.SeverityCritical: 5,
		event.Severity(0):      1, // default -> Informational
	}
	for sev, want := range ocsf {
		if got := ocsfSeverity(sev); got != want {
			t.Errorf("ocsfSeverity(%v) = %d; want %d", sev, got, want)
		}
	}
}

// TestMetaToString covers each type branch of metaToString, including the
// json.Marshal fallback path for a value that can't be marshalled.
func TestMetaToString(t *testing.T) {
	cases := []struct {
		name string
		in   any
		want string
	}{
		{"nil", nil, ""},
		{"string", "hello", "hello"},
		{"bool-true", true, "true"},
		{"bool-false", false, "false"},
		{"int", 42, "42"},
		{"int64", int64(-7), "-7"},
		{"float", 3.5, "3.5"},
		{"slice", []string{"a", "b"}, `["a","b"]`},
		{"map", map[string]int{"x": 1}, `{"x":1}`},
	}
	for _, c := range cases {
		if got := metaToString(c.in); got != c.want {
			t.Errorf("metaToString(%s) = %q; want %q", c.name, got, c.want)
		}
	}
	// A channel can't be JSON-marshalled; metaToString must fall back to a
	// %v rendering rather than returning an empty/garbage value.
	if got := metaToString(make(chan int)); !strings.HasPrefix(got, "0x") && got == "" {
		t.Errorf("metaToString(chan) = %q; want a non-empty %%v fallback", got)
	}
}

// TestEscapeValuesCoverSpecialBytes drives every branch of the CEF and LEEF
// extension-value escapers: the backslash, the format-specific special char,
// the CR/LF/TAB named escapes, and the \xHH control-byte path.
func TestEscapeValuesCoverSpecialBytes(t *testing.T) {
	// backslash, equals (CEF-special), CR, LF, TAB, a control byte, DEL, plain.
	in := "a\\b=c\r\n\td\x01e\x7ff"
	cef := cefEscapeValue(in)
	for _, want := range []string{`\\`, `\=`, `\r`, `\n`, `\t`, `\x01`, `\x7f`} {
		if !strings.Contains(cef, want) {
			t.Errorf("cefEscapeValue(%q) = %q; missing %q", in, cef, want)
		}
	}
	// LEEF escapes tab (its delimiter) rather than equals.
	leef := leefEscapeValue(in)
	for _, want := range []string{`\\`, `\t`, `\r`, `\n`, `\x01`, `\x7f`} {
		if !strings.Contains(leef, want) {
			t.Errorf("leefEscapeValue(%q) = %q; missing %q", in, leef, want)
		}
	}
	// A plain equals must survive LEEF unescaped (only CEF escapes it).
	if !strings.Contains(leef, "=c") {
		t.Errorf("leefEscapeValue should not escape '='; got %q", leef)
	}
}
