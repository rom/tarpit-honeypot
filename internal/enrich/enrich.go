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
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/oschwald/maxminddb-golang"

	"github.com/rom/tarpit-honeypot/internal/event"
)

type Config struct {
	CityDB     string        // path to GeoLite2-City.mmdb
	ASNDB      string        // path to GeoLite2-ASN.mmdb
	RDNSEnabled bool
	RDNSTimeout time.Duration
	RDNSCache   int
}

type Enricher struct {
	cityDB *maxminddb.Reader
	asnDB  *maxminddb.Reader
	rdns   *rdnsCache
}

func New(cfg Config) (*Enricher, error) {
	e := &Enricher{}
	if cfg.CityDB != "" {
		r, err := maxminddb.Open(cfg.CityDB)
		if err != nil {
			return nil, fmt.Errorf("enrich: open city db %s: %w", cfg.CityDB, err)
		}
		e.cityDB = r
		slog.Info("enrich: city db loaded", "path", cfg.CityDB, "build_epoch", r.Metadata.BuildEpoch)
	}
	if cfg.ASNDB != "" {
		r, err := maxminddb.Open(cfg.ASNDB)
		if err != nil {
			if e.cityDB != nil {
				_ = e.cityDB.Close()
			}
			return nil, fmt.Errorf("enrich: open asn db %s: %w", cfg.ASNDB, err)
		}
		e.asnDB = r
		slog.Info("enrich: asn db loaded", "path", cfg.ASNDB, "build_epoch", r.Metadata.BuildEpoch)
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
	return e, nil
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
	if e == nil || ev == nil || ev.Source.IP == "" {
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
			ASN       uint32 `maxminddb:"autonomous_system_number"`
			ASNOrg    string `maxminddb:"autonomous_system_organization"`
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
