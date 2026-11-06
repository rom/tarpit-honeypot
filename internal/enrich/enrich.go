// Package enrich decorates events with information that downstream SIEMs
// would otherwise have to look up: GeoIP country/city, ASN/AS-org, and
// reverse-DNS for source IPs.
//
// The enricher is called from the sensor's bus loop between the listener
// emission and the correlator, so aggregate events also inherit the
// enrichment without extra lookups.
//
// All databases are operator-supplied (MaxMind GeoLite2 license restricts
// redistribution). Both .mmdb paths are optional; if one is missing that
// dimension stays empty rather than failing the whole pipeline.
package enrich

import (
	"bufio"
	"context"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/oschwald/maxminddb-golang"

	"github.com/rom/tarpit-honeypot/internal/devices"
	"github.com/rom/tarpit-honeypot/internal/event"
)

type Config struct {
	CityDB      string // path to GeoLite2-City.mmdb
	ASNDB       string // path to GeoLite2-ASN.mmdb
	RDNSEnabled bool
	RDNSTimeout time.Duration
	RDNSCache   int
	// ThreatLists are operator-supplied IP/CIDR reputation lists, each
	// tagged with a label. A source matching any list gets a
	// threat_intel tag (the labels) on its events.
	ThreatLists []ThreatList
	// TorExitFile is an operator-supplied list of Tor exit-node IPs (one
	// per line). Matching sources get tor_exit=true.
	TorExitFile string
	// NetClass enables the built-in network classification (bogon /
	// cloud-hosting) that needs no external database.
	NetClass bool
	// CloudRanges are operator-supplied cloud-provider IP/CIDR lists (one
	// CIDR per line), each tagged with the provider name. A source inside a
	// range gets an authoritative cloud_provider tag (AWS / GCP / Azure /
	// DigitalOcean / …) — far more precise than the asn_org keyword heuristic.
	CloudRanges []CloudRangeList
	// FingerprintSources are fingerprint→client/tool databases (JA4DB / JA3 /
	// HASSH corpora), one per kind. A recognized fingerprint tags the event
	// <kind>_client with the named application / library / malware.
	FingerprintSources []FingerprintSource
}

// ThreatList is one labeled IP/CIDR reputation list.
type ThreatList struct {
	Label string
	File  string
}

// CloudRangeList is one cloud provider's published IP-range file.
type CloudRangeList struct {
	Provider string
	File     string
}

type Enricher struct {
	cityDB   *maxminddb.Reader
	asnDB    *maxminddb.Reader
	rdns     *rdnsCache
	threat   []threatSet
	cloud    []threatSet // cloud-provider ranges (label = provider name)
	fpdb     fpDB        // fingerprint -> client/tool attribution
	torExit  map[string]struct{}
	netClass bool

	// fleet intel is the downward-fed overlay (set by intel.Puller, read by
	// Decorate): value->reason maps for source IPs, ASNs, and "<kind>:<value>"
	// fingerprints the fleet flagged. Guarded separately so the puller can
	// refresh it concurrently with the bus-loop Decorate.
	fiMu   sync.RWMutex
	fiIPs  map[string]string
	fiASNs map[string]string
	fiFPs  map[string]string

	// extMu guards the external-feed overlay: source IP -> label from
	// operator-configured external reputation feeds (AbuseIPDB / GreyNoise /
	// OTX / plain IP lists), refreshed by the feeds puller. A match tags the
	// event external_intel + threat_intel_hit so the risk / tarpit / severity
	// machinery acts on it, exactly like the fleet overlay.
	extMu  sync.RWMutex
	extIPs map[string]string
}

// SetFleetIntel replaces the downward fleet-intel overlay. Called by the intel
// puller each poll; an empty/zero feed clears it.
func (e *Enricher) SetFleetIntel(ips, asns, fps map[string]string) {
	e.fiMu.Lock()
	e.fiIPs, e.fiASNs, e.fiFPs = ips, asns, fps
	e.fiMu.Unlock()
}

// SetExternalIntel replaces the external-feed overlay (source IP -> label).
// Called by the feeds puller each poll; nil/empty clears it.
func (e *Enricher) SetExternalIntel(ips map[string]string) {
	e.extMu.Lock()
	e.extIPs = ips
	e.extMu.Unlock()
}

// threatSet is one loaded reputation list: exact IPs plus a CIDR set.
type threatSet struct {
	label string
	ips   map[string]struct{}
	cidrs cidrSet
}

func (ts *threatSet) match(addr netip.Addr) bool {
	if _, ok := ts.ips[addr.String()]; ok {
		return true
	}
	return ts.cidrs.contains(addr)
}

// cidrSet answers "does addr fall in any stored prefix?" in O(distinct prefix
// lengths) instead of O(number of prefixes): prefixes are bucketed by mask
// length, each bucket a map of network-address -> {}. A reputation/cloud feed
// with thousands of prefixes but a handful of common lengths (/24, /20, /16, …)
// is then matched with a handful of map lookups per event rather than a linear
// scan over every prefix on the single-threaded bus loop. Built once at load
// (newCIDRSet); read-only afterward, so lookups need no lock. Family-strict,
// exactly like netip.Prefix.Contains (a v4 query never matches a v6 prefix).
type cidrSet struct {
	byLen map[int]map[netip.Addr]struct{}
	lens  []int // distinct prefix lengths present, longest first
}

func newCIDRSet(prefixes []netip.Prefix) cidrSet {
	var c cidrSet
	for _, p := range prefixes {
		if !p.IsValid() {
			continue
		}
		p = p.Masked()
		l := p.Bits()
		if c.byLen == nil {
			c.byLen = map[int]map[netip.Addr]struct{}{}
		}
		m := c.byLen[l]
		if m == nil {
			m = map[netip.Addr]struct{}{}
			c.byLen[l] = m
			c.lens = append(c.lens, l)
		}
		m[p.Addr()] = struct{}{}
	}
	sort.Sort(sort.Reverse(sort.IntSlice(c.lens)))
	return c
}

func (c cidrSet) contains(addr netip.Addr) bool {
	if c.byLen == nil || !addr.IsValid() {
		return false
	}
	bits := addr.BitLen()
	for _, l := range c.lens {
		if l > bits {
			continue // a prefix longer than this address family can't match
		}
		if _, ok := c.byLen[l][netip.PrefixFrom(addr, l).Masked().Addr()]; ok {
			return true
		}
	}
	return false
}

// New builds an Enricher. Enrichment databases are OPTIONAL and best-effort:
// a configured file that is missing or unreadable is logged and skipped (the
// sensor still starts), so an operator can declare the enrichment paths up
// front and populate them later (fetch-enrichment.sh + install-enrichment.sh
// + SIGHUP). New only returns an error for a non-file setup problem.
func New(cfg Config) (*Enricher, error) {
	e := &Enricher{}
	if cfg.CityDB != "" {
		if r, err := maxminddb.Open(cfg.CityDB); err != nil {
			slog.Warn("enrich: geoip city db unavailable; geo enrichment off", "path", cfg.CityDB, "err", err)
		} else {
			e.cityDB = r
			slog.Info("enrich: city db loaded", "path", cfg.CityDB, "build_epoch", r.Metadata.BuildEpoch)
		}
	}
	if cfg.ASNDB != "" {
		if r, err := maxminddb.Open(cfg.ASNDB); err != nil {
			slog.Warn("enrich: geoip asn db unavailable; asn enrichment off", "path", cfg.ASNDB, "err", err)
		} else {
			e.asnDB = r
			slog.Info("enrich: asn db loaded", "path", cfg.ASNDB, "build_epoch", r.Metadata.BuildEpoch)
		}
	}
	if cfg.RDNSEnabled {
		size := cfg.RDNSCache
		if size <= 0 {
			size = 1024
		}
		timeout := cfg.RDNSTimeout
		if timeout <= 0 {
			timeout = 500 * time.Millisecond
		}
		e.rdns = newRDNSCache(size, timeout)
	}
	for _, tl := range cfg.ThreatLists {
		if tl.File == "" {
			continue
		}
		label := tl.Label
		if label == "" {
			label = "threat"
		}
		ips, cidrs, n, err := loadIPList(tl.File)
		if err != nil {
			slog.Warn("enrich: threat list unavailable; skipping", "label", label, "path", tl.File, "err", err)
			continue
		}
		e.threat = append(e.threat, threatSet{label: label, ips: ips, cidrs: newCIDRSet(cidrs)})
		slog.Info("enrich: threat list loaded", "label", label, "path", tl.File, "entries", n)
	}
	for _, cr := range cfg.CloudRanges {
		if cr.File == "" || cr.Provider == "" {
			continue
		}
		ips, cidrs, n, err := loadIPList(cr.File)
		if err != nil {
			slog.Warn("enrich: cloud range list unavailable; skipping", "provider", cr.Provider, "path", cr.File, "err", err)
			continue
		}
		e.cloud = append(e.cloud, threatSet{label: cr.Provider, ips: ips, cidrs: newCIDRSet(cidrs)})
		slog.Info("enrich: cloud range list loaded", "provider", cr.Provider, "path", cr.File, "entries", n)
	}
	if cfg.TorExitFile != "" {
		if ips, _, n, err := loadIPList(cfg.TorExitFile); err != nil {
			slog.Warn("enrich: tor exit list unavailable; tor tagging off", "path", cfg.TorExitFile, "err", err)
		} else {
			e.torExit = ips
			slog.Info("enrich: tor exit list loaded", "path", cfg.TorExitFile, "entries", n)
		}
	}
	if len(cfg.FingerprintSources) > 0 {
		db, n, errs := loadFingerprintDB(cfg.FingerprintSources)
		for _, err := range errs {
			slog.Warn("enrich: fingerprint db source unavailable; skipping", "err", err)
		}
		if n > 0 {
			e.fpdb = db
			slog.Info("enrich: fingerprint db loaded", "entries", n, "kinds", len(db))
		}
	}
	e.netClass = cfg.NetClass
	return e, nil
}

// loadIPList reads a file of one IP or CIDR per line (blank lines and
// '#' comments ignored). Exact IPs go into the returned set (keyed by the
// canonical netip string); CIDRs go into the prefix slice. n is the count
// of parsed entries.
func loadIPList(path string) (ips map[string]struct{}, cidrs []netip.Prefix, n int, err error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, 0, err
	}
	defer func() { _ = f.Close() }()
	ips = map[string]struct{}{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if i := strings.IndexAny(line, " \t#"); i >= 0 { // allow trailing comments / columns
			line = strings.TrimSpace(line[:i])
		}
		if strings.Contains(line, "/") {
			if p, perr := netip.ParsePrefix(line); perr == nil {
				cidrs = append(cidrs, p.Masked())
				n++
			}
			continue
		}
		if a, aerr := netip.ParseAddr(line); aerr == nil {
			ips[a.String()] = struct{}{}
			n++
		}
	}
	if serr := sc.Err(); serr != nil {
		return nil, nil, 0, serr
	}
	return ips, cidrs, n, nil
}

func (e *Enricher) Close() error {
	if e == nil {
		return nil
	}
	if e.cityDB != nil {
		_ = e.cityDB.Close()
	}
	if e.asnDB != nil {
		_ = e.asnDB.Close()
	}
	return nil
}

// Decorate mutates ev.Meta in place. Skips IPs that are loopback,
// link-local, or already in RFC 1918 / RFC 4193 private ranges — they
// don't have meaningful geolocation and the rdns lookup would just
// return an internal name (or hang).
func (e *Enricher) Decorate(ev *event.Event) {
	if e == nil || ev == nil {
		return
	}
	// MAC-vendor enrichment runs regardless of source IP — DHCP/ARP events
	// often carry a MAC with a zeroed or private source address.
	decorateMAC(ev)
	if ev.Source.IP == "" {
		return
	}
	addr, err := netip.ParseAddr(ev.Source.IP)
	if err != nil {
		return
	}
	if addr.IsLoopback() || addr.IsLinkLocalUnicast() || addr.IsPrivate() {
		return
	}
	if ev.Meta == nil {
		ev.Meta = map[string]any{}
	}
	if e.cityDB != nil {
		var rec struct {
			Country struct {
				ISOCode string            `maxminddb:"iso_code"`
				Names   map[string]string `maxminddb:"names"`
			} `maxminddb:"country"`
			City struct {
				Names map[string]string `maxminddb:"names"`
			} `maxminddb:"city"`
			Location struct {
				Latitude  float64 `maxminddb:"latitude"`
				Longitude float64 `maxminddb:"longitude"`
			} `maxminddb:"location"`
		}
		if err := e.cityDB.Lookup(net.ParseIP(ev.Source.IP), &rec); err == nil {
			if rec.Country.ISOCode != "" {
				ev.Meta["geo_country"] = rec.Country.ISOCode
			}
			if n := rec.Country.Names["en"]; n != "" {
				ev.Meta["geo_country_name"] = n
			}
			if n := rec.City.Names["en"]; n != "" {
				ev.Meta["geo_city"] = n
			}
			if rec.Location.Latitude != 0 || rec.Location.Longitude != 0 {
				ev.Meta["geo_lat"] = rec.Location.Latitude
				ev.Meta["geo_lon"] = rec.Location.Longitude
			}
		}
	}
	if e.asnDB != nil {
		var rec struct {
			ASN    uint32 `maxminddb:"autonomous_system_number"`
			ASNOrg string `maxminddb:"autonomous_system_organization"`
		}
		if err := e.asnDB.Lookup(net.ParseIP(ev.Source.IP), &rec); err == nil {
			if rec.ASN != 0 {
				ev.Meta["asn"] = rec.ASN
			}
			if rec.ASNOrg != "" {
				ev.Meta["asn_org"] = rec.ASNOrg
			}
		}
	}
	if e.rdns != nil {
		if name, verified := e.rdns.lookupFull(ev.Source.IP); name != "" {
			ev.Meta["rdns"] = name
			// Forward-confirmed reverse DNS: a PTR that claims a well-known
			// crawler/cloud operator (googlebot.com, search.msn.com, …) is
			// confirmed by a forward lookup. A claim that doesn't confirm is a
			// spoofed PTR — a high-signal evasion marker (posing as Googlebot to
			// dodge blocks), surfaced as spoofed_ptr / spoofed_crawler.
			switch verified {
			case 1:
				ev.Meta["rdns_verified"] = true
				if c := crawlerClaim(name); c != "" {
					ev.Meta["verified_crawler"] = c
				}
			case -1:
				ev.Meta["rdns_verified"] = false
				ev.Meta["spoofed_ptr"] = true
				if c := crawlerClaim(name); c != "" {
					ev.Meta["spoofed_crawler"] = c
				}
			}
		}
	}
	// Known network-scanner infrastructure (Censys / Shodan / BinaryEdge /
	// Shadowserver / Rapid7 / etc.) identified at the IP level from the ASN
	// organization or reverse-DNS — so a scan is attributed even when the probe
	// carries no self-identifying User-Agent.
	if sc := KnownScanner(metaString(ev.Meta, "asn_org"), metaString(ev.Meta, "rdns")); sc != "" {
		ev.Meta["known_scanner"] = sc
	}
	if len(e.threat) > 0 {
		var hits []string
		for i := range e.threat {
			if e.threat[i].match(addr) {
				hits = append(hits, e.threat[i].label)
			}
		}
		if len(hits) > 0 {
			ev.Meta["threat_intel"] = hits
			ev.Meta["threat_intel_hit"] = true
		}
	}
	if e.torExit != nil {
		if _, ok := e.torExit[addr.String()]; ok {
			ev.Meta["tor_exit"] = true
		}
	}
	// Authoritative cloud-provider tag from published IP ranges (first match
	// wins). More precise than the asn_org keyword heuristic below.
	for i := range e.cloud {
		if e.cloud[i].match(addr) {
			ev.Meta["cloud_provider"] = e.cloud[i].label
			break
		}
	}
	if e.netClass {
		if cls := classifyNet(addr, ev.Meta["asn_org"]); cls != "" {
			ev.Meta["net_class"] = cls
		}
	}
	e.decorateFingerprints(ev)
	e.decorateFleetIntel(ev)
	e.decorateExternalIntel(ev)
	// Runs last: it reads the reputation meta the steps above set.
	decorateReputationConfidence(ev)
}

// decorateReputationConfidence counts how many INDEPENDENT reputation signals
// flagged the source — operator threat-lists (each matched label), the external
// feed overlay, and the downward fleet overlay (each reason) — and records
// threat_intel_count plus a coarse threat_confidence (low/medium/high).
//
// Several independent feeds agreeing is a far stronger signal than any single
// list (the premise of aggregated feeds like IPsum), so this gives the operator
// and the risk scorer a corroboration score to prioritize on. Research scanners
// and Tor exits are deliberately NOT counted — they're context, not a verdict
// of maliciousness.
func decorateReputationConfidence(ev *event.Event) {
	if ev == nil || len(ev.Meta) == 0 {
		return
	}
	n := 0
	if hits, ok := ev.Meta["threat_intel"].([]string); ok {
		n += len(hits)
	}
	if reasons, ok := ev.Meta["fleet_intel"].([]string); ok {
		n += len(reasons)
	}
	if _, ok := ev.Meta["external_intel"]; ok {
		n++
	}
	if n == 0 {
		return
	}
	ev.Meta["threat_intel_count"] = n
	switch {
	case n >= 3:
		ev.Meta["threat_confidence"] = "high"
	case n == 2:
		ev.Meta["threat_confidence"] = "medium"
	default:
		ev.Meta["threat_confidence"] = "low"
	}
}

// decorateExternalIntel tags an event whose source IP appears in an external
// reputation feed, setting external_intel (the feed label) and threat_intel_hit
// so the downstream risk / tarpit / severity machinery treats it as hostile.
func (e *Enricher) decorateExternalIntel(ev *event.Event) {
	if ev == nil || ev.Source.IP == "" {
		return
	}
	e.extMu.RLock()
	ips := e.extIPs
	e.extMu.RUnlock()
	if len(ips) == 0 {
		return
	}
	if label, ok := ips[ev.Source.IP]; ok {
		if ev.Meta == nil {
			ev.Meta = map[string]any{}
		}
		ev.Meta["external_intel"] = label
		ev.Meta["threat_intel_hit"] = true
	}
}

// decorateFleetIntel tags an event whose source IP, ASN, or fingerprint appears
// in the downward fleet-intel overlay. It also sets threat_intel_hit so the
// existing threat-intel-burst correlator and risk scoring act on fleet
// knowledge with no extra wiring.
func (e *Enricher) decorateFleetIntel(ev *event.Event) {
	e.fiMu.RLock()
	ips, asns, fps := e.fiIPs, e.fiASNs, e.fiFPs
	e.fiMu.RUnlock()
	if len(ips) == 0 && len(asns) == 0 && len(fps) == 0 {
		return
	}
	var reasons []string
	if r, ok := ips[ev.Source.IP]; ok {
		reasons = append(reasons, "ip:"+r)
	}
	if asn, _ := ev.Meta["asn"].(string); asn != "" {
		if r, ok := asns[asn]; ok {
			reasons = append(reasons, "asn:"+r)
		}
	}
	for _, k := range []string{"ja3", "ja4", "hassh"} {
		if v, _ := ev.Meta[k].(string); v != "" {
			if r, ok := fps[k+":"+v]; ok {
				reasons = append(reasons, "fp:"+r)
			}
		}
	}
	if len(reasons) > 0 {
		ev.Meta["fleet_intel"] = reasons
		ev.Meta["threat_intel_hit"] = true
	}
}

// decorateMAC tags an event with the OUI vendor of any MAC it carries
// (client_mac / sender_mac / mac), via the devices OUI table — the small
// built-in set, or the full IEEE registry when one was loaded with
// devices.LoadOUIFile. Sets ev.Meta["mac_vendor"].
func decorateMAC(ev *event.Event) {
	if ev.Meta == nil {
		return
	}
	var mac string
	for _, k := range []string{"client_mac", "sender_mac", "mac"} {
		if s, ok := ev.Meta[k].(string); ok && s != "" {
			mac = s
			break
		}
	}
	if mac == "" {
		return
	}
	if v := devices.VendorForMAC(mac); v != "" {
		ev.Meta["mac_vendor"] = v
	}
}

// bogons are ranges that must never appear as a legitimate public source
// (RFC 5737 TEST-NET, RFC 6598 CGNAT, RFC 2544 benchmark, Class E, the
// IPv6 documentation block, …). A source inside one is spoofed / martian
// — a high-signal anomaly for a sensor on the public edge.
var bogons = func() []netip.Prefix {
	cidrs := []string{
		"0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24",
		"192.88.99.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24",
		"240.0.0.0/4", "255.255.255.255/32",
		"::/128", "2001:db8::/32", "100::/64",
	}
	out := make([]netip.Prefix, 0, len(cidrs))
	for _, c := range cidrs {
		if p, err := netip.ParsePrefix(c); err == nil {
			out = append(out, p)
		}
	}
	return out
}()

// hostingKeywords are AS-org substrings that mark a source as datacenter /
// cloud infrastructure rather than a residential / corporate access network
// — a useful triage hint (scanners and C2 ride hosting, not eyeballs).
var hostingKeywords = []string{
	"amazon", "aws", "google", "microsoft", "azure", "oracle", "ovh",
	"hetzner", "digitalocean", "linode", "akamai", "cloudflare", "fastly",
	"alibaba", "tencent", "huawei cloud", "contabo", "leaseweb", "vultr",
	"choopa", "scaleway", "m247", "datacamp", "data center", "datacenter",
	"hosting", "colocation", "colo", "vps", "dedicated server",
}

// classifyNet returns a coarse network class for a public source: "bogon"
// for a reserved/martian range, "hosting" when the AS-org looks like a
// datacenter/cloud provider, else "".
func classifyNet(addr netip.Addr, asnOrg any) string {
	for _, p := range bogons {
		if p.Contains(addr) {
			return "bogon"
		}
	}
	if org, ok := asnOrg.(string); ok && org != "" {
		lo := strings.ToLower(org)
		for _, kw := range hostingKeywords {
			if strings.Contains(lo, kw) {
				return "hosting"
			}
		}
	}
	return ""
}

// rdnsMaxInFlight caps concurrent reverse-DNS resolutions. Each resolve is a
// short-lived goroutine (bounded by the per-lookup timeout), so a config reload
// that drops the cache leaks nothing — in-flight resolves just finish and exit.
const rdnsMaxInFlight = 8

// rdnsCache is a tiny LRU + per-IP timeout wrapper around net.LookupAddr.
//
// Lookups are NON-BLOCKING: a cache hit returns the cached name immediately; a
// miss returns "" at once and kicks off an asynchronous resolution (at most
// rdnsMaxInFlight in flight, one per IP), so the single-threaded sensor bus loop
// never stalls on a DNS round-trip — the defining honeypot workload is a flood
// of distinct source IPs, i.e. nearly all misses. A later event for the same IP
// picks up the resolved (or negatively-cached) name. Results, including "no
// name", are cached for 15 minutes so a failing IP isn't re-queried per event.
type rdnsCache struct {
	timeout time.Duration
	size    int
	sem     chan struct{} // bounds concurrent in-flight resolutions

	mu      sync.Mutex
	m       map[string]rdnsEntry
	lru     []string            // most-recently used at end; front gets evicted
	pending map[string]struct{} // IPs with a resolve goroutine in flight

	// lookupAddr performs the PTR query; a seam so tests can resolve without
	// real DNS. Defaults to the Go resolver.
	lookupAddr func(ctx context.Context, ip string) ([]string, error)
	// lookupHost forward-resolves a hostname to IPs for FCrDNS crawler
	// verification; a seam so tests resolve without real DNS. Defaults to the
	// Go resolver.
	lookupHost func(ctx context.Context, host string) ([]string, error)
}

type rdnsEntry struct {
	name      string
	expiresAt time.Time
	// verified records forward-confirmed reverse DNS for PTR names that claim a
	// well-known crawler/cloud operator: 0 = not applicable (no crawler claim),
	// 1 = forward-confirmed, -1 = claim failed confirmation (spoofed PTR).
	verified int8
}

func newRDNSCache(size int, timeout time.Duration) *rdnsCache {
	return &rdnsCache{
		timeout:    timeout,
		size:       size,
		sem:        make(chan struct{}, rdnsMaxInFlight),
		m:          map[string]rdnsEntry{},
		pending:    map[string]struct{}{},
		lookupAddr: (&net.Resolver{PreferGo: true}).LookupAddr,
		lookupHost: (&net.Resolver{PreferGo: true}).LookupHost,
	}
}

// lookup returns the cached PTR name (or "" on a miss / no PTR), kicking off an
// async resolve on a miss. It is the name-only convenience wrapper over
// lookupFull.
func (c *rdnsCache) lookup(ip string) string {
	name, _ := c.lookupFull(ip)
	return name
}

// lookupFull returns the cached PTR name and its FCrDNS verdict (see
// rdnsEntry.verified). A miss returns ("", 0) immediately and triggers an async
// resolve; a later sighting of the same IP picks up the resolved name/verdict.
func (c *rdnsCache) lookupFull(ip string) (string, int8) {
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	if e, ok := c.m[ip]; ok && e.expiresAt.After(now) {
		return e.name, e.verified // hit (name may be "" = resolved, no PTR)
	}
	// Miss: never block the caller. Trigger one async resolve per IP, subject to
	// the in-flight cap; otherwise skip and let a later sighting retry.
	if _, inflight := c.pending[ip]; !inflight {
		select {
		case c.sem <- struct{}{}:
			c.pending[ip] = struct{}{}
			go c.resolve(ip)
		default:
			// at the concurrency cap — drop; a later event for this IP retries.
		}
	}
	return "", 0
}

// resolve performs the blocking PTR lookup off the bus loop and caches the
// result (positive or negative). When the PTR claims a well-known crawler/cloud
// operator it is forward-confirmed (FCrDNS) so a spoofed PTR can be flagged.
// Runs in its own goroutine; releases its in-flight slot on return.
func (c *rdnsCache) resolve(ip string) {
	defer func() {
		c.mu.Lock()
		delete(c.pending, ip)
		c.mu.Unlock()
		<-c.sem
	}()
	ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
	defer cancel()
	var name string
	var verified int8
	if names, err := c.lookupAddr(ctx, ip); err == nil && len(names) > 0 {
		name = strings.TrimSuffix(names[0], ".")
		if crawlerClaim(name) != "" {
			verified = c.confirmForward(ctx, ip, name)
		}
	}
	c.store(ip, name, verified)
}

// confirmForward implements forward-confirmed reverse DNS: it forward-resolves
// the PTR name and returns 1 when the result contains the original IP, or -1
// when it does not (a PTR that claims a crawler but can't be confirmed — a
// spoofed record). Only called for crawler-claiming PTR names.
func (c *rdnsCache) confirmForward(ctx context.Context, ip, name string) int8 {
	want, err := netip.ParseAddr(ip)
	if err != nil {
		return 0
	}
	hosts, err := c.lookupHost(ctx, name)
	if err != nil || len(hosts) == 0 {
		return -1 // claims a crawler but has no (resolvable) forward record
	}
	for _, h := range hosts {
		if a, e := netip.ParseAddr(strings.TrimSpace(h)); e == nil && a == want {
			return 1
		}
	}
	return -1
}

func (c *rdnsCache) store(ip, name string, verified int8) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.m[ip]; !ok {
		c.lru = append(c.lru, ip)
		if len(c.lru) > c.size {
			oldest := c.lru[0]
			c.lru = c.lru[1:]
			delete(c.m, oldest)
		}
	}
	c.m[ip] = rdnsEntry{name: name, verified: verified, expiresAt: time.Now().Add(15 * time.Minute)}
}

// crawlerClaims maps a well-known crawler/cloud PTR suffix to the operator it
// implies. Attackers routinely set a fake PTR such as "crawl-x.googlebot.com"
// to masquerade as a trusted crawler and dodge rate limits / blocks; the
// FCrDNS check (confirmForward) catches the ones that don't forward-confirm.
var crawlerClaims = []struct{ suffix, name string }{
	{".googlebot.com", "googlebot"},
	{".google.com", "google"},
	{".search.msn.com", "bingbot"},
	{".crawl.baidu.com", "baidu"},
	{".crawl.baidu.jp", "baidu"},
	{".yandex.com", "yandex"},
	{".yandex.ru", "yandex"},
	{".yandex.net", "yandex"},
	{".crawl.yahoo.net", "yahoo"},
	{".applebot.apple.com", "applebot"},
	{".ahrefs.com", "ahrefs"},
	{".semrush.com", "semrush"},
}

// crawlerClaim returns the crawler/cloud operator a PTR name claims to belong
// to (by DNS suffix), or "" when it claims none.
func crawlerClaim(ptr string) string {
	p := strings.ToLower(strings.TrimSuffix(ptr, "."))
	for _, c := range crawlerClaims {
		if strings.HasSuffix(p, c.suffix) {
			return c.name
		}
	}
	return ""
}
