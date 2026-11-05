package handler

import "strings"

// Shared helpers for the IoT / IIoT / OT / infrastructure UDP handlers added in
// the protocol-coverage expansion. They keep every new handler short and make
// the capture-only posture (no reply, so no amplification) the default.

// captureUDP builds the standard capture-only Result: a deep copy of the
// datagram, an initialized Meta map, the byte length, and a single anomaly
// marker. Handlers layer protocol-specific Meta keys on top.
func captureUDP(payload []byte, anomaly string) Result {
	res := Result{Payload: append([]byte(nil), payload...), Meta: map[string]any{}}
	res.Meta["bytes"] = len(payload)
	if anomaly != "" {
		flagAnomaly(&res, anomaly)
	}
	return res
}

// indexFold is a case-insensitive strings.Index.
func indexFold(s, sub string) int {
	return strings.Index(strings.ToLower(s), strings.ToLower(sub))
}

// hasPrefixFold is a case-insensitive strings.HasPrefix.
func hasPrefixFold(s, prefix string) bool {
	if len(s) < len(prefix) {
		return false
	}
	return strings.EqualFold(s[:len(prefix)], prefix)
}

// xmlTagValue returns the text between the first <tag ...> and </tag> (any
// namespace prefix on the tag is ignored). "" if not found. Bounded, naive —
// just enough to surface a probe's declared SOAP/XML fields, never to parse.
func xmlTagValue(body, tag string) string {
	// Case-insensitive search over the original bytes (asciiIndexFold): ToLower
	// is not length-preserving, so indexing a lowercased copy and slicing body
	// can mis-slice or panic.
	tl := strings.ToLower(tag)
	// match ":tag>" or "<tag>" / "<tag " allowing a namespace prefix.
	open := -1
	for _, pat := range []string{"<" + tl + ">", "<" + tl + " ", ":" + tl + ">", ":" + tl + " "} {
		if i := asciiIndexFold(body, pat); i >= 0 {
			if g := strings.IndexByte(body[i:], '>'); g >= 0 {
				open = i + g + 1
				break
			}
		}
	}
	if open < 0 || open >= len(body) {
		return ""
	}
	end := asciiIndexFold(body[open:], "</")
	if end < 0 {
		return strings.TrimSpace(body[open:])
	}
	return strings.TrimSpace(body[open : open+end])
}
