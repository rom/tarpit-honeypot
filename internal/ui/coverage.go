package ui

import (
	"net/http"
	"time"
)

// CoverageCounts is the headline capability summary on /coverage: what the
// running sensor actively recognizes and emulates, pulled live from the
// compile-time catalogs + runtime overlay state.
type CoverageCounts struct {
	TCPHandlers   int
	UDPHandlers   int
	CVETotal      int
	CVEDetectable int // records carrying an exploit signature (live-matched)
	CVEAdvisory   int // version/banner-emulation + KEV-marking only
	KEVActive     bool
	KEVEntries    int // entries in the live CISA KEV overlay
	KEVUpdated    time.Time
	KEVModeled    int // modeled CVEs currently KEV-listed (0 when overlay off)
	RulesLoaded   int
	RulesHits     uint64
	Techniques    int
	Tactics       int
	Archetypes    int
}

// CoverageServiceRow is one emulated service (handler) and the exploit
// recognition the CVE catalog gives it.
type CoverageServiceRow struct {
	Service    string
	Detectable int
	Advisory   int
	KEV        int // of this service's CVEs, how many are KEV-listed right now
	TopCVE     string
	TopName    string
	TopCVSS    float64
}

// CoverageLabel documents one enrichment / recognition label the sensor can
// stamp on a source — the "emulations / recognition" half of the page.
type CoverageLabel struct {
	Glyph string
	Label string
	Desc  string
}

// CoverageView is the whole /coverage page: a live capability snapshot.
type CoverageView struct {
	Counts   CoverageCounts
	Services []CoverageServiceRow // sorted by (detectable+advisory) desc
	Labels   []CoverageLabel      // recognition-label catalog (ui-side static)
}

// CoverageProvider returns a live capability snapshot. nil = the page is
// hidden (the sensor didn't wire it).
type CoverageProvider func() CoverageView

// SetCoverageProvider wires the capability snapshot so the /coverage page can
// enumerate the active handlers, CVE recognition, KEV overlay, detection
// rules, and recognition labels. Populated by the run command from the
// compile-time catalogs (internal/cve, internal/config, internal/mitre) and
// the running sensor's KEV / detection state.
func (s *Server) SetCoverageProvider(p CoverageProvider) { s.coverage = p }

func (s *Server) handleCoverage(w http.ResponseWriter, r *http.Request) {
	if s.coverage == nil {
		http.NotFound(w, r)
		return
	}
	v := s.coverage()
	if len(v.Labels) == 0 {
		v.Labels = recognitionLabelCatalog()
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tmpl.ExecuteTemplate(w, "coverage", v); err != nil {
		serverError(w, r.URL.Path, err)
	}
}

// recognitionLabelCatalog is the fixed set of enrichment / recognition labels
// the sensor stamps on a source, mirrored from sourceBadges so the page stays
// in sync with what actually renders on the events table. It is documentation,
// not live data, so it lives ui-side.
func recognitionLabelCatalog() []CoverageLabel {
	return []CoverageLabel{
		{"🛡", "threat_confidence", "Cross-feed reputation confidence (low/medium/high) — how many independent blocklists corroborate the source."},
		{"🎭", "spoofed_ptr", "Reverse-DNS claims a search-engine crawler but fails forward-confirmation (deliberate evasion)."},
		{"🕵", "anonymizer / anonymized", "Source is in a Tor / VPN / open-proxy range."},
		{"☠", "asn_reputation", "Source ASN is on a reputation list (Spamhaus ASN-DROP / bulletproof hosting)."},
		{"🧭", "asn_geo_mismatch", "ASN's registered country differs from the GeoIP country (routing / geo anomaly)."},
		{"🏴", "geo_risk", "Source geolocated to an operator-configured high-risk country."},
		{"🔑", "cred_class", "Captured login's credential class: default / weak / breached / unique."},
		{"🧬", "dns_dga", "Queried an algorithmically-generated-looking (DGA) domain."},
		{"🌐", "domain_bad", "Queried a known-malicious domain (operator blocklist)."},
		{"", "blacklist / threat / intel", "On a reputation list (operator or external feed), or a fleet-derived indicator."},
		{"", "tor", "Known Tor exit node."},
		{"", "scanner:<tool>", "Known internet-scanning infrastructure, or a self-identified scanner from the client fingerprint."},
		{"", "cloud:<provider> / hosting", "Authoritative cloud-provider range, or datacenter/hosting net-class (rented infra, not residential)."},
		{"", "bogon", "Spoofed / reserved (bogon) source address."},
		{"⚑", "meta:deceptive-origin", "Composite: the source misrepresents where it is from (spoofed crawler PTR, ASN↔geo mismatch, or a residential PTR on a hosting net)."},
		{"⚑", "meta:corroborated-threat", "Composite: two or more independent reputation signals (threat confidence, blocklist, ASN-DROP, bad domain, spoofed PTR) agree."},
		{"⚑", "meta:targeted-recon", "Composite: a high-value target (ICS/OT, database, remote-access) probed from hidden (Tor/VPN/proxy) or rented (cloud/hosting) infrastructure."},
		{"⚑", "meta:ot-recon", "Composite: an ICS/OT target probed from hidden/rented infrastructure."},
		{"⚑", "meta:credential-foothold", "Composite: a weak/default/breached captured login against a remote-access or cloud/devops target."},
	}
}
