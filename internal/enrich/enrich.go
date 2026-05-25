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
}

// ThreatList is one labeled IP/CIDR reputation list.
type ThreatList struct {
	Label string
	File  string
}

type Enricher struct {
	cityDB   *maxminddb.Reader
	asnDB    *maxminddb.Reader
	rdns     *rdnsCache
	threat   []threatSet
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
}

// SetFleetIntel replaces the downward fleet-intel overlay. Called by the intel
// puller each poll; an empty/zero feed clears it.
func (e *Enricher) SetFleetIntel(ips, asns, fps map[string]string) {
	e.fiMu.Lock()
	e.fiIPs, e.fiASNs, e.fiFPs = ips, asns, fps
	e.fiMu.Unlock()
}

// threatSet is one loaded reputation list: exact IPs plus CIDR prefixes.
type threatSet struct {
	label string
	ips   map[string]struct{}
	cidrs []netip.Prefix
}

func (ts *threatSet) match(addr netip.Addr) bool {
	if _, ok := ts.ips[addr.String()]; ok {
		return true
	}
	for _, p := range ts.cidrs {
		if p.Contains(addr) {
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
		e.threat = append(e.threat, threatSet{label: label, ips: ips, cidrs: cidrs})
		slog.Info("enrich: threat list loaded", "label", label, "path", tl.File, "entries", n)
	}
	if cfg.TorExitFile != "" {
		if ips, _, n, err := loadIPList(cfg.TorExitFile); err != nil {
			slog.Warn("enrich: tor exit list unavailable; tor tagging off", "path", cfg.TorExitFile, "err", err)
		} else {
			e.torExit = ips
			slog.Info("enrich: tor exit list loaded", "path", cfg.TorExitFile, "entries", n)
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
		if name := e.rdns.lookup(ev.Source.IP); name != "" {
			ev.Meta["rdns"] = name
		}
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
	if e.netClass {
		if cls := classifyNet(addr, ev.Meta["asn_org"]); cls != "" {
			ev.Meta["net_class"] = cls
		}
	}
	e.decorateFleetIntel(ev)
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

// rdnsCache is a tiny LRU + per-IP timeout wrapper around net.LookupAddr.
// Synchronous on first lookup (with timeout) so events get decorated on
// the same pass; subsequent events for the same IP hit the cache.
type rdnsCache struct {
	timeout time.Duration
	size    int

	mu  sync.Mutex
	m   map[string]rdnsEntry
	lru []string // most-recently used at end; front gets evicted
}

type rdnsEntry struct {
	name      string
	expiresAt time.Time
}

func newRDNSCache(size int, timeout time.Duration) *rdnsCache {
	return &rdnsCache{
		timeout: timeout,
		size:    size,
		m:       map[string]rdnsEntry{},
	}
}

func (c *rdnsCache) lookup(ip string) string {
	now := time.Now()
	c.mu.Lock()
	if e, ok := c.m[ip]; ok && e.expiresAt.After(now) {
		c.mu.Unlock()
		return e.name
	}
	c.mu.Unlock()

	// Perform the DNS lookup with our timeout.
	ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
	defer cancel()
	var name string
	r := net.Resolver{PreferGo: true}
	names, err := r.LookupAddr(ctx, ip)
	if err == nil && len(names) > 0 {
		name = names[0]
		if l := len(name); l > 0 && name[l-1] == '.' {
			name = name[:l-1]
		}
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	c.m[ip] = rdnsEntry{name: name, expiresAt: now.Add(15 * time.Minute)}
	c.lru = append(c.lru, ip)
	if len(c.lru) > c.size {
		oldest := c.lru[0]
		c.lru = c.lru[1:]
		delete(c.m, oldest)
	}
	return name
}
