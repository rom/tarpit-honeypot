package artifactscan

import (
	"math"
	"regexp"
	"sort"
	"strings"
)

// shannonEntropy returns the Shannon entropy of b in bits/byte (0..8). High
// values (>7.2) indicate compression / encryption / packing.
func shannonEntropy(b []byte) float64 {
	if len(b) == 0 {
		return 0
	}
	var counts [256]int
	for _, c := range b {
		counts[c]++
	}
	n := float64(len(b))
	var h float64
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		h -= p * math.Log2(p)
	}
	return h
}

// extractStrings returns printable ASCII and UTF-16LE strings of at least
// minLen runes found in b, deduplicated and capped at max entries. Control
// bytes are excluded so the output is safe to embed in events/logs.
func extractStrings(b []byte, minLen, max int) []string {
	seen := map[string]struct{}{}
	var out []string
	add := func(s string) {
		if len(s) < minLen {
			return
		}
		if _, ok := seen[s]; ok {
			return
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	// ASCII runs.
	var cur strings.Builder
	for _, c := range b {
		if c >= 0x20 && c < 0x7f {
			cur.WriteByte(c)
		} else {
			add(cur.String())
			cur.Reset()
		}
	}
	add(cur.String())
	// UTF-16LE runs (ASCII char followed by 0x00).
	cur.Reset()
	for i := 0; i+1 < len(b); i += 2 {
		if b[i] >= 0x20 && b[i] < 0x7f && b[i+1] == 0x00 {
			cur.WriteByte(b[i])
		} else {
			add(cur.String())
			cur.Reset()
		}
	}
	add(cur.String())
	if len(out) > max {
		out = out[:max]
	}
	return out
}

// IOCs are indicators harvested from an artifact's printable strings.
type IOCs struct {
	URLs    []string `json:"urls,omitempty"`
	IPv4    []string `json:"ipv4,omitempty"`
	Domains []string `json:"domains,omitempty"`
	Emails  []string `json:"emails,omitempty"`
	Bitcoin []string `json:"bitcoin,omitempty"`
	Onion   []string `json:"onion,omitempty"`
}

// Empty reports whether no indicators were found.
func (i IOCs) Empty() bool {
	return len(i.URLs)+len(i.IPv4)+len(i.Domains)+len(i.Emails)+len(i.Bitcoin)+len(i.Onion) == 0
}

var (
	reURL     = regexp.MustCompile(`(?i)\b(?:https?|ftp|tftp)://[^\s"'<>)\]]{4,}`)
	reIPv4    = regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b`)
	reEmail   = regexp.MustCompile(`(?i)\b[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}\b`)
	reOnion   = regexp.MustCompile(`(?i)\b[a-z2-7]{16,56}\.onion\b`)
	reBitcoin = regexp.MustCompile(`\b(?:bc1[a-z0-9]{25,90}|[13][a-km-zA-HJ-NP-Z1-9]{25,39})\b`)
	reDomain  = regexp.MustCompile(`(?i)\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b`)
)

// extractIOCs harvests indicators from the strings of b. Domains are filtered
// to plausible TLDs and de-noised against common false positives. Each list
// is capped to keep event payloads bounded.
func extractIOCs(strs []string, cap int) IOCs {
	joined := strings.Join(strs, "\n")
	var i IOCs
	i.URLs = dedupCap(reURL.FindAllString(joined, -1), cap)
	i.IPv4 = dedupCap(filterIPs(reIPv4.FindAllString(joined, -1)), cap)
	i.Emails = dedupCap(reEmail.FindAllString(joined, -1), cap)
	i.Onion = dedupCap(lowerAll(reOnion.FindAllString(joined, -1)), cap)
	i.Bitcoin = dedupCap(reBitcoin.FindAllString(joined, -1), cap)
	i.Domains = dedupCap(filterDomains(reDomain.FindAllString(joined, -1)), cap)
	return i
}

func filterIPs(ips []string) []string {
	var out []string
	for _, ip := range ips {
		// Drop version-string-like 0.0.0.0 / 1.2.3.4 placeholders sparingly:
		// keep everything routable-looking; only strip the obvious 0.0.0.0.
		if ip == "0.0.0.0" || ip == "127.0.0.1" || ip == "255.255.255.255" {
			continue
		}
		out = append(out, ip)
	}
	return out
}

// commonFileSuffixes are domain-regex false positives: filenames like
// "kernel32.dll" or "config.json" match the domain shape.
var commonFileSuffixes = map[string]bool{
	"dll": true, "exe": true, "sys": true, "so": true, "dylib": true,
	"json": true, "xml": true, "html": true, "php": true, "asp": true,
	"png": true, "jpg": true, "gif": true, "txt": true, "log": true,
	"dat": true, "bin": true, "tmp": true, "cfg": true, "ini": true,
	"py": true, "js": true, "go": true, "c": true, "h": true, "cpp": true,
}

func filterDomains(ds []string) []string {
	var out []string
	for _, d := range ds {
		d = strings.ToLower(d)
		dot := strings.LastIndexByte(d, '.')
		if dot < 0 {
			continue
		}
		tld := d[dot+1:]
		if commonFileSuffixes[tld] {
			continue // looks like a filename, not a domain
		}
		out = append(out, d)
	}
	return out
}

func lowerAll(s []string) []string {
	for i := range s {
		s[i] = strings.ToLower(s[i])
	}
	return s
}

func dedupCap(in []string, cap int) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, s := range in {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
		if cap > 0 && len(out) >= cap {
			break
		}
	}
	sort.Strings(out)
	return out
}
