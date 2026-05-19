package format

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/rom/tarpit-honeypot/internal/event"
)

type cefF struct{}

func (c *cefF) Name() string        { return "cef" }
func (c *cefF) ContentType() string { return "text/plain; charset=utf-8" }

// CEF: ArcSight Common Event Format v0.
//
//   CEF:0|Vendor|Product|Version|SignatureID|Name|Severity|Extension
//
// Pipes in the prefix fields are backslash-escaped; equals and
// backslashes in the extension key=value pairs are backslash-escaped.
// Severity maps low=2, medium=5, high=7, critical=10 — the standard CEF
// mapping that ArcSight uses.
func (c *cefF) Format(ev *event.Event) ([]byte, error) {
	var b strings.Builder
	b.WriteString("CEF:0|")
	b.WriteString(cefEscapeHeader(Vendor))
	b.WriteByte('|')
	b.WriteString(cefEscapeHeader(Product))
	b.WriteByte('|')
	b.WriteString(cefEscapeHeader(ProductVN))
	b.WriteByte('|')
	b.WriteString(cefEscapeHeader(ev.RuleID))
	b.WriteByte('|')
	b.WriteString(cefEscapeHeader(cefName(ev)))
	b.WriteByte('|')
	b.WriteString(strconv.Itoa(cefSeverity(ev.Severity)))
	b.WriteByte('|')

	// Extension: standard ArcSight keys for the network event class.
	writeKV := func(k, v string) {
		if v == "" {
			return
		}
		if b.Len() > 0 && !strings.HasSuffix(b.String(), "|") {
			b.WriteByte(' ')
		}
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(cefEscapeValue(v))
	}
	writeKV("rt", strconv.FormatInt(ev.Time.UTC().UnixMilli(), 10))
	writeKV("externalId", ev.ID)
	writeKV("dvchost", ev.Sensor)
	writeKV("src", ev.Source.IP)
	if ev.Source.Port > 0 {
		writeKV("spt", strconv.Itoa(ev.Source.Port))
	}
	writeKV("dst", ev.Dest.IP)
	if ev.Dest.Port > 0 {
		writeKV("dpt", strconv.Itoa(ev.Dest.Port))
	}
	writeKV("proto", strings.ToUpper(ev.Proto))
	writeKV("app", ev.Handler)
	// Meta -> cs1..cs6 + cs1Label..cs6Label slots, capped at 6.
	if len(ev.Meta) > 0 {
		i := 1
		for _, k := range sortedMetaKeys(ev.Meta) {
			if i > 6 {
				break
			}
			v := metaToString(ev.Meta[k])
			if v == "" {
				continue
			}
			writeKV("cs"+strconv.Itoa(i)+"Label", k)
			writeKV("cs"+strconv.Itoa(i), v)
			i++
		}
	}
	return []byte(b.String()), nil
}

// cefName returns a short human-readable event description for the Name
// header field. Maps known rule_id prefixes onto cleaner names.
func cefName(ev *event.Event) string {
	switch {
	case strings.HasPrefix(ev.RuleID, "listener:"):
		return "Honeypot listener triggered"
	case strings.HasPrefix(ev.RuleID, "canary:url:"):
		return "URL canary triggered"
	case strings.HasPrefix(ev.RuleID, "canary:dns:"):
		return "DNS canary triggered"
	case strings.HasPrefix(ev.RuleID, "canary:"):
		return "File canary triggered"
	case strings.HasPrefix(ev.RuleID, "correlate:port_scan"):
		return "Port scan detected"
	case strings.HasPrefix(ev.RuleID, "correlate:brute_force"):
		return "Brute-force detected"
	case strings.HasPrefix(ev.RuleID, "correlate:slow_scan"):
		return "Slow scan detected"
	case strings.HasPrefix(ev.RuleID, "sniffer:arp_scan"):
		return "ARP scan detected"
	case strings.HasPrefix(ev.RuleID, "sniffer:arp_reply_unsolicited"):
		return "Unsolicited ARP reply"
	case strings.HasPrefix(ev.RuleID, "dnscanary"):
		return "DNS canary listener event"
	case strings.HasPrefix(ev.RuleID, "sensor:reload"):
		return "Sensor configuration reload"
	}
	return ev.RuleID
}

// cefSeverity maps tarpit-honeypot severities to ArcSight CEF's 0-10 scale.
func cefSeverity(s event.Severity) int {
	switch s {
	case event.SeverityLow:
		return 2
	case event.SeverityMedium:
		return 5
	case event.SeverityHigh:
		return 7
	case event.SeverityCritical:
		return 10
	}
	return 0
}

// cefEscapeHeader escapes characters that are special in the pipe-separated
// header portion: only backslash and pipe.
func cefEscapeHeader(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `|`, `\|`)
	return s
}

// cefEscapeValue escapes characters that are special in the extension
// key=value portion: backslash, equals, and any control character.
// We don't just translate \r\n to "\n" / "\r" sequences because an
// attacker-supplied banner could still contain raw escape sequences
// (\x1b[...), NUL bytes, or other terminal-jacking content. Anything
// outside printable ASCII is replaced with a literal \xHH so the
// output is safe to pipe into a log file or `tail -f` window.
func cefEscapeValue(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\\':
			b.WriteString(`\\`)
		case c == '=':
			b.WriteString(`\=`)
		case c == '\n':
			b.WriteString(`\n`)
		case c == '\r':
			b.WriteString(`\r`)
		case c == '\t':
			b.WriteString(`\t`)
		case c < 0x20 || c == 0x7F:
			fmt.Fprintf(&b, `\x%02x`, c)
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}
