package enrich

import (
	"github.com/rom/tarpit-honeypot/internal/event"
	"github.com/rom/tarpit-honeypot/internal/toolfp"
)

// decorateFingerprintTools turns the network fingerprints the handlers stamp on
// an event (ja3 / ja4 / ja4h TLS-HTTP, hassh SSH) into live tool attribution and
// automation signals. Until now those fingerprints were computed and stored but
// only mapped to a tool by the offline `identify` CLI — so a JA3/JA4/HASSH that
// matched a known stack never labelled a live event. This closes that gap and
// adds a corpus-free check: a browser User-Agent on a non-browser TLS handshake
// is a spoofed UA (the handshake is far harder to forge than the UA string).
//
// It is fingerprint-driven and IP-class-independent, so it runs before the
// GeoIP/ASN path (which early-returns for private/loopback sources). A no-op
// when the event carries no fingerprint, so events without TLS/SSH are untouched.
func decorateFingerprintTools(ev *event.Event) {
	if ev == nil || ev.Meta == nil {
		return
	}
	m := ev.Meta
	var found []string
	if v := metaString(m, "ja3"); v != "" {
		if t := toolfp.IdentifyTLS(v); t != "" {
			found = appendUniqueTool(found, t)
		}
	}
	for _, k := range []string{"ja4", "ja4h"} {
		if v := metaString(m, k); v != "" {
			if t := toolfp.IdentifyJA4(v); t != "" {
				found = appendUniqueTool(found, t)
			}
		}
	}
	if v := metaString(m, "hassh"); v != "" {
		if t := toolfp.IdentifyHASSH(v); t != "" {
			found = appendUniqueTool(found, t)
		}
	}

	// JA4 automation heuristic — reliable without any signature DB.
	automation := false
	if ja4 := metaString(m, "ja4"); ja4 != "" {
		if reason, auto := toolfp.JA4Automation(ja4); auto {
			automation = true
			m["tls_automation"] = reason
			// A browser UA on a non-browser TLS stack is a forged User-Agent.
			if ua := metaString(m, "user_agent"); ua != "" && toolfp.LooksLikeBrowserUA(ua) {
				m["spoofed_ua"] = true
				ev.Anomalies = appendUniqueTool(ev.Anomalies, "spoofed-user-agent")
			}
		}
	}

	if len(found) == 0 && !automation {
		return
	}
	if len(found) > 0 {
		// Merge into the event's tool set (the UA path may already have added
		// some) and mark that a fingerprint — not a self-identified UA — is the
		// source, so a SOC can tell forge-resistant attribution apart.
		merged := existingTools(m["tools"])
		for _, t := range found {
			merged = appendUniqueTool(merged, t)
			ev.Anomalies = appendUniqueTool(ev.Anomalies, "tool:"+t)
		}
		m["tools"] = merged
		m["fp_tool"] = true
	}
}

// existingTools reads a meta["tools"] value (stored as []string or []any) into a
// fresh []string, so a merge never mutates the stored slice in place.
func existingTools(v any) []string {
	switch t := v.(type) {
	case []string:
		out := make([]string, len(t))
		copy(out, t)
		return out
	case []any:
		out := make([]string, 0, len(t))
		for _, e := range t {
			if s, ok := e.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// appendUniqueTool appends s to list unless already present (case-sensitive).
func appendUniqueTool(list []string, s string) []string {
	for _, e := range list {
		if e == s {
			return list
		}
	}
	return append(list, s)
}
