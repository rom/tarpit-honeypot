package enrich

import (
	"crypto/sha256"
	"encoding/hex"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/rom/tarpit-honeypot/internal/event"
)

// decorateAttributes adds derived, no-external-data attributes: a subnet
// aggregation key, a reverse-DNS connection-type guess, session novelty flags,
// a high-risk-geo flag, the source's local hour, a stable actor id, and a
// coarse targeting label. It reads meta set earlier in Decorate, so it runs
// near the end of the pipeline.
func (e *Enricher) decorateAttributes(ev *event.Event, addr netip.Addr) {
	// Subnet aggregation key — a botnet spread across one block reads as one
	// actor (/24 for IPv4, /48 for IPv6).
	netKey := subnetKey(addr)
	if netKey != "" {
		ev.Meta["src_net"] = netKey
	}

	// Connection type guessed from the PTR name (residential/dynamic vs
	// hosting/static). Residential ~= compromised host / proxy; hosting ~= bot.
	if ct := connType(metaString(ev.Meta, "rdns")); ct != "" {
		ev.Meta["conn_type"] = ct
	}

	// High-risk geography (operator-configured ISO country set).
	if len(e.riskCountries) > 0 {
		if _, ok := e.riskCountries[metaString(ev.Meta, "geo_country")]; ok {
			ev.Meta["geo_risk"] = true
		}
	}

	// Source-local hour of day from the GeoIP timezone — recognizes "automated
	// at 3am local" vs interactive hours. Needs system tzdata; skipped if the
	// zone can't be loaded.
	if tz := metaString(ev.Meta, "geo_timezone"); tz != "" && !ev.Time.IsZero() {
		if loc, err := time.LoadLocation(tz); err == nil {
			ev.Meta["src_local_hour"] = ev.Time.In(loc).Hour()
		}
	}

	// Anonymizer rollup: Tor exit, or a feed-backed VPN/proxy tag (set by the
	// anonymizer ranges loader). One flag for rules to key on.
	if boolMeta(ev.Meta, "tor_exit") || metaString(ev.Meta, "anonymizer") != "" {
		ev.Meta["anonymized"] = true
	}

	// Session novelty — first sight (this process lifetime) of the source's
	// ASN / subnet / fingerprint.
	if asn := metaASNKey(ev.Meta); asn != "" && e.firstSight(e.seenASN, asn) {
		ev.Meta["novel_asn"] = true
	}
	if netKey != "" && e.firstSight(e.seenNet, netKey) {
		ev.Meta["novel_subnet"] = true
	}

	// Stable actor id from the strongest available fingerprint, else a UA hash
	// — groups the same tool/operator across rotating IPs.
	if id := actorID(ev.Meta); id != "" {
		ev.Meta["actor_id"] = id
		if e.firstSight(e.seenFP, id) {
			ev.Meta["novel_fingerprint"] = true
		}
	}

	// Coarse "what are they hunting" label from the rule/handler.
	if t := targeting(ev); t != "" {
		ev.Meta["targeting"] = t
	}
}

// subnetKey returns the aggregation prefix for addr: /24 for IPv4, /48 for IPv6
// (4-in-6 is treated as IPv4).
func subnetKey(addr netip.Addr) string {
	a := addr.Unmap()
	bits := 48
	if a.Is4() {
		bits = 24
	}
	p, err := a.Prefix(bits)
	if err != nil {
		return ""
	}
	return p.String()
}

var dashedIPRe = regexp.MustCompile(`(^|[.-])\d{1,3}[.-]\d{1,3}[.-]\d{1,3}[.-]\d{1,3}([.-]|$)`)

var residentialRDNS = []string{
	"dynamic", "dyn.", "dyn-", "dsl", "pppoe", "ppp", "dhcp", "cable",
	"broadband", "res.", "residential", "cpe", "dial", "pool", "wireless",
	"mobile", "cust.", "customer", ".rev.", "fibertel", "veloip",
}

var hostingRDNS = []string{
	"static", "dedicated", "dedi", "colo", "vps", "server", "srv", "hosted",
	"hosting", "cloud", "datacenter", "data-center",
}

// connType classifies a PTR hostname as "residential" or "hosting" (or "").
// Keyword hits win first; otherwise a bare dashed-IP-in-hostname pattern
// (e.g. 1-2-3-4.isp.net) is a strong residential/dynamic signal.
func connType(rdns string) string {
	if rdns == "" {
		return ""
	}
	h := strings.ToLower(rdns)
	for _, k := range residentialRDNS {
		if strings.Contains(h, k) {
			return "residential"
		}
	}
	for _, k := range hostingRDNS {
		if strings.Contains(h, k) {
			return "hosting"
		}
	}
	if dashedIPRe.MatchString(h) {
		return "residential"
	}
	return ""
}

// actorID returns a stable grouping id for the client behind the event: the
// strongest network fingerprint if present, else a short hash of the User-Agent.
func actorID(m map[string]any) string {
	for _, k := range []string{"ja4", "ja3", "hassh", "ja4h"} {
		if v := metaString(m, k); v != "" {
			return k + ":" + v
		}
	}
	if ua := metaString(m, "user_agent"); ua != "" {
		sum := sha256.Sum256([]byte(ua))
		return "ua:" + hex.EncodeToString(sum[:])[:12]
	}
	return ""
}

// metaASNKey renders the event's ASN meta (stored as uint32 by the ASN lookup)
// as an "AS<n>" key, or "" when absent.
func metaASNKey(m map[string]any) string {
	switch v := m["asn"].(type) {
	case uint32:
		if v != 0 {
			return "AS" + strconv.FormatUint(uint64(v), 10)
		}
	case int:
		if v != 0 {
			return "AS" + strconv.Itoa(v)
		}
	case int64:
		if v != 0 {
			return "AS" + strconv.FormatInt(v, 10)
		}
	case string:
		return v
	}
	return ""
}

// targeting maps the rule/handler to a coarse "what are they hunting" label.
func targeting(ev *event.Event) string {
	hay := strings.ToLower(ev.RuleID + " " + ev.Handler)
	switch {
	case containsAny(hay, "wordpress", "wp-", "wp_", "joomla", "drupal", "phpmyadmin", "php2shell", "webapp", "cms"):
		return "web-cms"
	case containsAny(hay, "exchange", "owa", "smtp", "imap", "pop3", "webmail"):
		return "mail"
	case containsAny(hay, "modbus", "s7", "iec104", "dnp3", "bacnet", "profinet", "ethernetip", "opcua", "ics", "scada", "tristation", "codesys", "melsec", "hartip", "mms", "pcworx", "ge_srtp", "atg"):
		return "ics-ot"
	case containsAny(hay, "tr069", "upnp", "tr369", "mikrotik", "fortinet", "pulse", "citrix", "moxa", "router", "iot"):
		return "iot-edge"
	case containsAny(hay, "mysql", "postgres", "mssql", "oracle", "mongodb", "redis", "memcached", "rethinkdb", "database"):
		return "database"
	case containsAny(hay, "ssh", "rdp", "vnc", "telnet", "winrm", "teamviewer", "anydesk", "rlogin", "x11", "citrix_ica"):
		return "remote-access"
	case containsAny(hay, "docker", "kubernetes", "etcd", "vault", "cloud_metadata", "ssrf"):
		return "cloud-devops"
	}
	return ""
}

func containsAny(h string, subs ...string) bool {
	for _, s := range subs {
		if strings.Contains(h, s) {
			return true
		}
	}
	return false
}

func boolMeta(m map[string]any, k string) bool {
	b, _ := m[k].(bool)
	return b
}
