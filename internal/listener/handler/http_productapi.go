package handler

import (
	"strings"

	"github.com/rom/tarpit-honeypot/internal/archetype"
)

// serveProductAPI returns a believable response body + content-type for the
// well-known web/API base paths of the process-historian / data-platform
// archetypes (PI Web API, Proficy, Canary, dataPARC, AVEVA/Wonderware,
// Ignition, InfluxDB, Keycloak, Guacamole). It is gated on the archetype's
// quirks so only the matching product answers its own paths; everything else
// falls through to the normal decoy response. ok=false means "not mine".
//
// The bodies are static, plausible product shapes (no live data) — enough that
// a scanner that *queries the API* (not just the homepage) records a real
// product, and the probe is flagged. It never executes anything.
func serveProductAPI(arch *archetype.Profile, method, path string) (body, contentType string, ok bool) {
	if arch == nil || path == "" {
		return "", "", false
	}
	p := strings.ToLower(path)
	if i := strings.IndexByte(p, '?'); i >= 0 {
		p = p[:i]
	}
	host := arch.SNMPSysName()
	if host == "" {
		host = "server01"
	}
	const json = "application/json; charset=utf-8"
	const html = "text/html; charset=utf-8"

	switch {
	// ---- OSIsoft / AVEVA PI Web API ----
	case arch.HasQuirk("pi") && strings.HasPrefix(p, "/piwebapi"):
		base := "https://" + host + "/piwebapi"
		switch {
		case p == "/piwebapi" || p == "/piwebapi/":
			return `{"Links":{"Self":"` + base + `","System":"` + base + `/system","DataServers":"` + base + `/dataservers","AssetServers":"` + base + `/assetservers"}}`, json, true
		case strings.HasPrefix(p, "/piwebapi/dataservers"):
			return `{"Items":[{"WebId":"DS0AbCdEf","Name":"` + host + `","Path":"\\\\` + host + `","IsConnected":true,"ServerVersion":"3.4.445.688","Links":{"Self":"` + base + `/dataservers/DS0AbCdEf","Points":"` + base + `/dataservers/DS0AbCdEf/points"}}]}`, json, true
		case strings.HasPrefix(p, "/piwebapi/assetservers"):
			return `{"Items":[{"WebId":"AS0AbCdEf","Name":"PI-AF01","Path":"\\\\PI-AF01","Links":{"Self":"` + base + `/assetservers/AS0AbCdEf","Databases":"` + base + `/assetservers/AS0AbCdEf/assetdatabases"}}]}`, json, true
		default: // /piwebapi/system, /system/versions, …
			return `{"Links":{"Self":"` + base + `/system","Versions":"` + base + `/system/versions","CacheInstances":"` + base + `/system/cacheinstances","UserInfo":"` + base + `/system/userinfo"},"CachedInstances":1}`, json, true
		}

	// ---- GE Proficy Historian ----
	case arch.HasQuirk("proficy") && (strings.HasPrefix(p, "/proficyhistorian") || strings.HasPrefix(p, "/proficywebspace") || strings.HasPrefix(p, "/historian")):
		return `<!doctype html><html><head><title>Proficy Historian</title></head><body><h2>GE Proficy Historian Web Admin</h2><p>Historian ` + host + ` — Data Archiver online</p></body></html>`, html, true

	// ---- Canary ----
	case arch.HasQuirk("canary") && (strings.HasPrefix(p, "/canaryadmin") || strings.HasPrefix(p, "/canarydata")):
		if strings.HasPrefix(p, "/canarydata") {
			return `{"statusCode":"Good","historians":["` + host + `"]}`, json, true
		}
		return `<!doctype html><html><head><title>Canary</title></head><body><h2>Canary Admin</h2><p>` + host + ` — Sender/Receiver running</p></body></html>`, html, true

	// ---- dataPARC ----
	case arch.HasQuirk("dataparc") && (strings.HasPrefix(p, "/dataparc") || strings.HasPrefix(p, "/parcview")):
		return `<!doctype html><html><head><title>dataPARC</title></head><body><h2>PARCview</h2><p>dataPARC Historian ` + host + `</p></body></html>`, html, true

	// ---- AVEVA / Wonderware Historian ----
	case (arch.HasQuirk("wonderware") || arch.HasQuirk("aveva")) && (strings.HasPrefix(p, "/historian") || strings.HasPrefix(p, "/wonderware") || strings.HasPrefix(p, "/aveva")):
		return `<!doctype html><html><head><title>AVEVA Historian</title></head><body><h2>AVEVA Insight / Historian</h2><p>` + host + ` (Wonderware Historian)</p></body></html>`, html, true

	// ---- Inductive Automation Ignition ----
	case arch.HasQuirk("ignition") && (strings.HasPrefix(p, "/ignition") || strings.HasPrefix(p, "/vision") || strings.HasPrefix(p, "/web") || strings.HasPrefix(p, "/system/gwinfo")):
		if strings.HasPrefix(p, "/system/gwinfo") {
			return `{"platformEdition":"standard","gatewayName":"` + host + `","redundancyRole":"Independent","version":"8.1.34"}`, json, true
		}
		return `<!doctype html><html><head><title>Ignition Gateway</title></head><body><h2>Inductive Automation Ignition</h2><p>Gateway ` + host + ` 8.1.34</p></body></html>`, html, true

	// ---- InfluxDB ----
	case arch.HasQuirk("influxdb") && (p == "/health" || p == "/ping" || strings.HasPrefix(p, "/api/v2")):
		if p == "/ping" {
			return "", json, true // 204-ish; empty body is fine
		}
		return `{"name":"influxdb","message":"ready for queries and writes","status":"pass","version":"2.7.5"}`, json, true

	// ---- Keycloak (OIDC discovery is the first thing tools fetch) ----
	case arch.HasQuirk("keycloak") && strings.Contains(p, "/.well-known/openid-configuration"):
		realm := "https://" + host + "/realms/master"
		return `{"issuer":"` + realm + `","authorization_endpoint":"` + realm + `/protocol/openid-connect/auth","token_endpoint":"` + realm + `/protocol/openid-connect/token","jwks_uri":"` + realm + `/protocol/openid-connect/certs"}`, json, true

	// ---- Apache Guacamole ----
	case arch.HasQuirk("guacamole") && strings.HasPrefix(p, "/guacamole/api"):
		return `{"availableDataSources":["postgresql","mysql","default"]}`, json, true
	}
	return "", "", false
}
