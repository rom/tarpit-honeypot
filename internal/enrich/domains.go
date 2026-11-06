package enrich

import (
	"math"
	"strings"

	"github.com/rom/tarpit-honeypot/internal/event"
)

// domainMetaKeys are the meta keys that may carry an attacker-supplied domain
// (DNS query name, HTTP Host, TLS SNI).
var domainMetaKeys = []string{"qname", "query", "dns_query", "host", "sni", "domain"}

// decorateDomains flags a DGA-looking domain (dns_dga, heuristic, no data) and
// a known-malicious domain (domain_bad, from the operator blocklist) on any
// domain the event carries.
func (e *Enricher) decorateDomains(ev *event.Event) {
	raw, ok := firstMeta(ev.Meta, domainMetaKeys)
	if !ok {
		return
	}
	dom := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(raw)), ".")
	if dom == "" {
		return
	}
	if looksDGA(dom) {
		ev.Meta["dns_dga"] = true
	}
	if len(e.badDomains) > 0 && matchDomain(e.badDomains, dom) {
		ev.Meta["domain_bad"] = true
	}
}

// looksDGA is a conservative heuristic for algorithmically-generated domains:
// it examines the registrable (second-to-last) label and flags it only when it
// is long AND shows at least two randomness signals (high entropy, very low
// vowel ratio, a long consonant run, a high digit ratio). Tuned to spare normal
// domains; best-effort, never authoritative.
func looksDGA(domain string) bool {
	labels := strings.Split(domain, ".")
	if len(labels) < 2 {
		return false
	}
	return dgaLabel(labels[len(labels)-2])
}

func dgaLabel(s string) bool {
	if len(s) < 12 {
		return false
	}
	var digits, vowels, consRun, maxRun int
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9':
			digits++
			consRun = 0
		case strings.ContainsRune("aeiou", r):
			vowels++
			consRun = 0
		case r >= 'a' && r <= 'z':
			consRun++
			if consRun > maxRun {
				maxRun = consRun
			}
		default:
			consRun = 0
		}
	}
	n := float64(len(s))
	signals := 0
	if shannon(s) >= 3.5 {
		signals++
	}
	if float64(vowels)/n < 0.20 {
		signals++
	}
	if maxRun >= 5 {
		signals++
	}
	if float64(digits)/n >= 0.20 {
		signals++
	}
	return signals >= 2
}

// shannon returns the Shannon entropy (bits/char) of s.
func shannon(s string) float64 {
	if s == "" {
		return 0
	}
	var freq [256]float64
	for i := 0; i < len(s); i++ {
		freq[s[i]]++
	}
	n := float64(len(s))
	ent := 0.0
	for _, c := range freq {
		if c > 0 {
			p := c / n
			ent -= p * math.Log2(p)
		}
	}
	return ent
}

// matchDomain reports whether dom, or any registrable suffix of it, is in set
// (so sub.evil.com matches a blocklist entry of evil.com).
func matchDomain(set map[string]struct{}, dom string) bool {
	if _, ok := set[dom]; ok {
		return true
	}
	labels := strings.Split(dom, ".")
	for i := 1; i+1 < len(labels); i++ {
		if _, ok := set[strings.Join(labels[i:], ".")]; ok {
			return true
		}
	}
	return false
}
