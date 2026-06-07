package config

import "strings"

// TLSCoherenceWarnings reports where the TLS certificate identity the sensor
// will present diverges from the deployment domain the rest of the deception
// advertises (the DNS zone, SMTP HELO, Kerberos realm, NTLM target, …, all
// derived from sensor.domain). A mismatch is a fingerprinting tell: a scanner
// that sees a service answer for "corp.example.com" but hand back a certificate
// for "acme.test" (or the bare "localhost" default) learns it's talking to a
// decoy. The returned strings are human-readable, surfaced on the config page
// and logged once at startup. Empty slice = coherent (or nothing to check).
//
// What "the generated certificate" presents:
//   - sensor.tls_domain when set, else sensor.domain (see internal/sensor wiring
//     and handler.SetTLSDefaults); falls back to "localhost" only when both are
//     empty.
//   - a listener's https.hosts / https.cn override that, per service.
func (c *Config) TLSCoherenceWarnings() []string {
	dom := normDomain(c.Sensor.Domain)
	if dom == "" {
		// No deployment domain to be coherent with: the localhost default is a
		// reasonable standalone posture, so don't nag. (A tls_domain set without
		// a domain is unusual but harmless — the cert simply leads the identity.)
		return nil
	}
	tlsDom := normDomain(c.Sensor.TLSDomain)

	var out []string
	// Deployment-wide cert identity vs the service domain.
	if tlsDom != "" && !domainsCohere(tlsDom, dom) {
		out = append(out, "sensor.tls_domain "+quote(c.Sensor.TLSDomain)+
			" does not match the deployment domain "+quote(c.Sensor.Domain)+
			": TLS decoys will present a certificate whose name disagrees with the "+
			"DNS / SMTP / Kerberos identities derived from sensor.domain. Align "+
			"sensor.tls_domain with sensor.domain (or leave it unset to inherit it).")
	}

	// Per-listener https.hosts / https.cn overrides that pin a name off-domain.
	// The effective cert domain a host should fit under is tls_domain when set,
	// else the deployment domain.
	certDom := tlsDom
	if certDom == "" {
		certDom = dom
	}
	bad := map[string]bool{}
	var badList []string
	noteHost := func(listenerID, h string) {
		hn := normDomain(h)
		if hn == "" || isIPLike(hn) || hn == "localhost" {
			return // bare IPs / localhost SANs are deliberate, not a domain tell
		}
		if domainsCohere(hn, certDom) || domainsCohere(hn, dom) {
			return
		}
		k := listenerID + "\x00" + hn
		if !bad[k] {
			bad[k] = true
			badList = append(badList, "listener "+quote(listenerID)+" -> "+hn)
		}
	}
	for _, l := range c.Listeners {
		for _, h := range l.HTTPS.Hosts {
			noteHost(l.ID, h)
		}
		if cn := l.HTTPS.CN; cn != "" {
			noteHost(l.ID, cn)
		}
	}
	if len(badList) > 0 {
		out = append(out, "listener TLS host overrides pin certificate names off "+
			"the deployment domain "+quote(c.Sensor.Domain)+" ("+
			strings.Join(badList, "; ")+"): these services will present a name that "+
			"disagrees with the rest of the deployment identity.")
	}
	return out
}

// normDomain lower-cases, trims surrounding whitespace, and drops a leading dot
// so "Corp.Example.com" / ".corp.example.com" compare equal to "corp.example.com".
func normDomain(s string) string {
	return strings.TrimPrefix(strings.ToLower(strings.TrimSpace(s)), ".")
}

// domainsCohere reports whether two (already normalized) domain names belong to
// the same naming hierarchy: equal, one a subdomain of the other, or sharing the
// same registrable (last-two-label) domain — e.g. "mail.corp.example.com" and
// "corp.example.com" cohere, and so do "a.example.com" and "b.example.com".
func domainsCohere(a, b string) bool {
	if a == "" || b == "" {
		return true
	}
	if a == b {
		return true
	}
	if strings.HasSuffix(a, "."+b) || strings.HasSuffix(b, "."+a) {
		return true
	}
	return registrable(a) == registrable(b)
}

// registrable returns the last two labels of a dotted name ("example.com" from
// "mail.corp.example.com"), or the whole name when it has fewer than two dots.
// A coarse heuristic (no public-suffix list), enough to tell "same org domain"
// from "entirely different domain" for an operator-facing coherence hint.
func registrable(d string) string {
	parts := strings.Split(d, ".")
	if len(parts) <= 2 {
		return d
	}
	return strings.Join(parts[len(parts)-2:], ".")
}

// isIPLike reports whether a host looks like a bare IPv4/IPv6 literal rather
// than a DNS name (so we don't flag an IP SAN as an off-domain name).
func isIPLike(h string) bool {
	if strings.Contains(h, ":") {
		return true // IPv6 literal
	}
	for _, r := range h {
		if (r < '0' || r > '9') && r != '.' {
			return false
		}
	}
	return strings.Count(h, ".") == 3
}

// quote wraps a value in double quotes for the warning text (empty -> "(unset)").
func quote(s string) string {
	if strings.TrimSpace(s) == "" {
		return "(unset)"
	}
	return "\"" + s + "\""
}
