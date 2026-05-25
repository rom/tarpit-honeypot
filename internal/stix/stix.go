// Package stix renders the fleet's observed indicators (see internal/intel) as
// STIX 2.1 and serves them over a minimal read-only TAXII 2.1 API, so any STIX/
// TAXII-speaking SIEM or TIP can pull the IOCs the fleet has seen. Indicator IDs
// are deterministic (UUIDv5 of the pattern), so the same IOC keeps a stable id
// across snapshots and downstreams dedup cleanly.
package stix

import (
	"crypto/sha1"
	"crypto/subtle"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/rom/tarpit-honeypot/internal/intel"
)

// tarpitNamespace is a fixed UUID used as the UUIDv5 namespace for deterministic
// indicator ids (any constant UUID works; this one is ours).
var tarpitNamespace = [16]byte{
	0x9f, 0x2a, 0x1c, 0x77, 0x4b, 0x3e, 0x5d, 0x88,
	0xa1, 0x02, 0xc3, 0x44, 0xe5, 0x66, 0x77, 0x88,
}

// Indicator is a STIX 2.1 Indicator SDO (the subset we populate).
type Indicator struct {
	Type        string    `json:"type"`
	SpecVersion string    `json:"spec_version"`
	ID          string    `json:"id"`
	Created     time.Time `json:"created"`
	Modified    time.Time `json:"modified"`
	Name        string    `json:"name"`
	Description string    `json:"description,omitempty"`
	IndicTypes  []string  `json:"indicator_types"`
	Pattern     string    `json:"pattern"`
	PatternType string    `json:"pattern_type"`
	ValidFrom   time.Time `json:"valid_from"`
	Labels      []string  `json:"labels,omitempty"`
}

// Bundle is a STIX 2.1 Bundle.
type Bundle struct {
	Type    string        `json:"type"`
	ID      string        `json:"id"`
	Objects []interface{} `json:"objects"`
}

// Indicators converts the fleet IOCs into STIX 2.1 Indicator SDOs.
func Indicators(iocs []intel.IOC, now time.Time) []interface{} {
	out := make([]interface{}, 0, len(iocs))
	for _, ioc := range iocs {
		pattern, ok := patternFor(ioc)
		if !ok {
			continue
		}
		id := "indicator--" + uuidv5(pattern)
		out = append(out, Indicator{
			Type: "indicator", SpecVersion: "2.1", ID: id,
			Created: now, Modified: now,
			Name:        ioc.Kind + " " + ioc.Value,
			Description: "tarpit-honeypot fleet finding: " + ioc.Reason,
			IndicTypes:  []string{"malicious-activity"},
			Pattern:     pattern, PatternType: "stix",
			ValidFrom: now, Labels: []string{"malicious-activity"},
		})
	}
	return out
}

// NewBundle wraps indicators in a STIX bundle with a deterministic-ish id.
func NewBundle(objs []interface{}) Bundle {
	return Bundle{Type: "bundle", ID: "bundle--" + uuidv5(fmt.Sprintf("bundle-%d", len(objs))), Objects: objs}
}

// patternFor builds the STIX pattern for an IOC. IPs and ASNs use standard SCO
// patterns; fingerprints use a documented custom object (no native STIX type).
func patternFor(ioc intel.IOC) (string, bool) {
	switch ioc.Kind {
	case "ip":
		ip := net.ParseIP(ioc.Value)
		if ip == nil {
			return "", false
		}
		if ip.To4() != nil {
			return "[ipv4-addr:value = '" + ioc.Value + "']", true
		}
		return "[ipv6-addr:value = '" + ioc.Value + "']", true
	case "asn":
		num := strings.TrimPrefix(strings.TrimPrefix(ioc.Value, "AS"), "as")
		if num == "" || !allDigits(num) {
			return "", false
		}
		return "[autonomous-system:number = " + num + "]", true
	case "fingerprint":
		// No native STIX object for ja3/ja4/hassh; emit a custom-object pattern.
		return "[x-tarpit-fingerprint:value = '" + stixEscape(ioc.Value) + "']", true
	}
	return "", false
}

func allDigits(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func stixEscape(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, `\`, `\\`), `'`, `\'`)
}

// uuidv5 returns a name-based (SHA-1) UUID under tarpitNamespace, hex-formatted.
func uuidv5(name string) string {
	h := sha1.New()
	h.Write(tarpitNamespace[:])
	h.Write([]byte(name))
	sum := h.Sum(nil)
	var u [16]byte
	copy(u[:], sum[:16])
	u[6] = (u[6] & 0x0f) | 0x50 // version 5
	u[8] = (u[8] & 0x3f) | 0x80 // variant RFC 4122
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		binary.BigEndian.Uint32(u[0:4]), binary.BigEndian.Uint16(u[4:6]),
		binary.BigEndian.Uint16(u[6:8]), binary.BigEndian.Uint16(u[8:10]), u[10:16])
}

// Source supplies the current IOCs to the HTTP handlers.
type Source func() []intel.IOC

const (
	collectionID    = "fleet-iocs"
	taxiiMediaType  = "application/taxii+json;version=2.1"
	bundleMediaType = "application/json"
)

// Handler returns the combined STIX + TAXII 2.1 read API, bearer-gated. Routes:
//
//	GET /intel/stix                                   -> a STIX 2.1 bundle
//	GET /taxii2/                                      -> discovery
//	GET /taxii2/api/                                  -> api-root
//	GET /taxii2/api/collections/                      -> collections list
//	GET /taxii2/api/collections/fleet-iocs/           -> collection
//	GET /taxii2/api/collections/fleet-iocs/objects/   -> STIX objects envelope
func Handler(src Source, token string) http.Handler {
	mux := http.NewServeMux()
	auth := func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
			if token == "" || subtle.ConstantTimeCompare([]byte(got), []byte(token)) != 1 {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			h(w, r)
		}
	}
	writeJSON := func(w http.ResponseWriter, media string, v any) {
		w.Header().Set("Content-Type", media)
		_ = json.NewEncoder(w).Encode(v)
	}
	objects := func() []interface{} { return Indicators(src(), time.Now().UTC()) }

	mux.HandleFunc("/intel/stix", auth(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, bundleMediaType, NewBundle(objects()))
	}))
	mux.HandleFunc("/taxii2/", auth(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, taxiiMediaType, map[string]any{
			"title": "tarpit-honeypot fleet intel", "default": "/taxii2/api/",
			"api_roots": []string{"/taxii2/api/"},
		})
	}))
	mux.HandleFunc("/taxii2/api/", auth(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/taxii2/api/":
			writeJSON(w, taxiiMediaType, map[string]any{
				"title": "fleet intel api root", "versions": []string{"application/taxii+json;version=2.1"},
				"max_content_length": 1 << 20,
			})
		case "/taxii2/api/collections/":
			writeJSON(w, taxiiMediaType, map[string]any{"collections": []any{collectionObj()}})
		case "/taxii2/api/collections/" + collectionID + "/":
			writeJSON(w, taxiiMediaType, collectionObj())
		case "/taxii2/api/collections/" + collectionID + "/objects/":
			writeJSON(w, taxiiMediaType, map[string]any{
				"more": false, "objects": objects(),
			})
		default:
			http.Error(w, "not found", http.StatusNotFound)
		}
	}))
	return mux
}

func collectionObj() map[string]any {
	return map[string]any{
		"id": collectionID, "title": "Fleet IOCs",
		"description": "Indicators derived from tarpit-honeypot fleet:* findings",
		"can_read":    true, "can_write": false,
		"media_types": []string{"application/stix+json;version=2.1"},
	}
}
