package format

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/rom/tarpit-honeypot/internal/event"
)

type leefF struct{}

func (l *leefF) Name() string        { return "leef" }
func (l *leefF) ContentType() string { return "text/plain; charset=utf-8" }

// LEEF: IBM Log Event Extended Format v2.0.
//
//   LEEF:2.0|Vendor|Product|Version|EventID|DelimChar|Extension
//
// We declare the extension delimiter explicitly as a tab character (0x09)
// in the prefix so QRadar parses key=value pairs predictably even when
// values contain spaces. Severity is reported as a separate "sev" field
// in the extension (LEEF doesn't reserve a header slot for it like CEF).
func (l *leefF) Format(ev *event.Event) ([]byte, error) {
	const delim = "\t"
	var b strings.Builder
	b.WriteString("LEEF:2.0|")
	b.WriteString(leefEscapeHeader(Vendor))
	b.WriteByte('|')
	b.WriteString(leefEscapeHeader(Product))
	b.WriteByte('|')
	b.WriteString(leefEscapeHeader(ProductVN))
	b.WriteByte('|')
	b.WriteString(leefEscapeHeader(ev.RuleID))
	b.WriteByte('|')
	// Custom delimiter spec: a literal "x09" identifies tab. We use the
	// raw byte instead — both forms are spec-legal and the byte form is
	// what QRadar's default parser handles cleanly.
	b.WriteByte('\t')

	writeKV := func(k, v string) {
		if v == "" {
			return
		}
		if !strings.HasSuffix(b.String(), "\t") {
			b.WriteString(delim)
		}
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(leefEscapeValue(v))
	}
	writeKV("devTime", ev.Time.UTC().Format("Jan 2 2006 15:04:05"))
	writeKV("devTimeFormat", "MMM d yyyy HH:mm:ss")
	writeKV("eventId", ev.ID)
	writeKV("dvchost", ev.Sensor)
	writeKV("sev", ev.Severity.String())
	writeKV("src", ev.Source.IP)
	if ev.Source.Port > 0 {
		writeKV("srcPort", strconv.Itoa(ev.Source.Port))
	}
	writeKV("dst", ev.Dest.IP)
	if ev.Dest.Port > 0 {
		writeKV("dstPort", strconv.Itoa(ev.Dest.Port))
	}
	writeKV("proto", strings.ToUpper(ev.Proto))
	writeKV("app", ev.Handler)
	// Meta keys flow through as their native name (LEEF allows arbitrary
	// extension keys — no fixed slot count). Keep order deterministic.
	for _, k := range sortedMetaKeys(ev.Meta) {
		writeKV("meta_"+k, metaToString(ev.Meta[k]))
	}
	return []byte(b.String()), nil
}

func leefEscapeHeader(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `|`, `\|`)
	return s
}

// leefEscapeValue escapes every byte that could disturb LEEF parsing:
// our tab delimiter, the backslash escape char, line terminators, and
// any control character below 0x20. ANSI escapes / NUL / bell would
// otherwise survive a syslog hop and risk impersonating a different
// log line.
func leefEscapeValue(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\\':
			b.WriteString(`\\`)
		case c == '\t':
			b.WriteString(`\t`)
		case c == '\n':
			b.WriteString(`\n`)
		case c == '\r':
			b.WriteString(`\r`)
		case c < 0x20 || c == 0x7F:
			fmt.Fprintf(&b, `\x%02x`, c)
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}
