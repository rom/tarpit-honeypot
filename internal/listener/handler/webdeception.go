package handler

import (
	"html"
	"net"
	"strings"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/safe"
)

// Web deception: robots.txt, /.well-known/security.txt and sitemap.xml decoys
// for the http/https handler. The disallow + sitemap paths are honeypot bait —
// probing them is flagged — and the sitemap-listed pages are delivered slowly
// (a per-page tarpit) to waste a crawler's time. The security.txt contacts seed
// the cross-protocol honeytoken-account detector (see the sensor).

// robotsTxt builds a robots.txt whose Disallow entries tempt a recon tool into
// probing paths a real site would hide.
func robotsTxt(disallow []string) string {
	var b strings.Builder
	b.WriteString("User-agent: *\n")
	for _, p := range disallow {
		b.WriteString("Disallow: ")
		b.WriteString(safe.SanitizeForLog(p))
		b.WriteByte('\n')
	}
	b.WriteString("\nSitemap: /sitemap.xml\n")
	return b.String()
}

// securityTxt builds an RFC 9116 /.well-known/security.txt. The Contact
// addresses are honeytokens.
func securityTxt(contacts []string, policyURL, expires string) string {
	if expires == "" {
		expires = time.Now().AddDate(1, 0, 0).UTC().Format(time.RFC3339)
	}
	if policyURL == "" {
		policyURL = "/security-policy.txt"
	}
	var b strings.Builder
	b.WriteString("# Our security disclosure policy. Please report vulnerabilities\n")
	b.WriteString("# responsibly to the contacts below.\n")
	for _, c := range contacts {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		if !strings.Contains(c, ":") { // bare address -> mailto:
			c = "mailto:" + c
		}
		b.WriteString("Contact: ")
		b.WriteString(safe.SanitizeForLog(c))
		b.WriteByte('\n')
	}
	b.WriteString("Expires: ")
	b.WriteString(safe.SanitizeForLog(expires))
	b.WriteByte('\n')
	b.WriteString("Policy: ")
	b.WriteString(safe.SanitizeForLog(policyURL))
	b.WriteByte('\n')
	b.WriteString("Preferred-Languages: en\n")
	return b.String()
}

// sitemapXML lists the configured fake pages as a sitemap.
func sitemapXML(pages []string) string {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` + "\n")
	b.WriteString(`<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">` + "\n")
	for _, p := range pages {
		b.WriteString("  <url><loc>")
		b.WriteString(safe.SanitizeForLog(p))
		b.WriteString("</loc><changefreq>weekly</changefreq><priority>0.7</priority></url>\n")
	}
	b.WriteString("</urlset>\n")
	return b.String()
}

// sitemapPageHTML returns a believable, content-light HTML stub for a
// sitemap-listed page (served slowly by the tarpit).
func sitemapPageHTML(path string) string {
	title := strings.Trim(path, "/")
	if title == "" {
		title = "Home"
	}
	return "<!doctype html><html><head><title>" + html.EscapeString(title) +
		"</title></head><body><h1>" + html.EscapeString(title) + "</h1>" +
		"<p>This page is loading. Please wait…</p>" +
		"<p>If the content does not appear, contact your administrator.</p>" +
		"</body></html>"
}

// matchesDecoyPath reports whether the request path matches one of the bait
// paths (prefix match for directory-style entries, exact otherwise).
func matchesDecoyPath(path string, entries []string) bool {
	p := strings.ToLower(path)
	for _, e := range entries {
		e = strings.ToLower(strings.TrimSpace(e))
		if e == "" || e == "/" {
			// "/" (the site root) is never bait — it would match every path and
			// is served by the normal handler. Match it exactly only.
			if e == "/" && p == "/" {
				return true
			}
			continue
		}
		if strings.HasSuffix(e, "/") {
			if strings.HasPrefix(p, e) {
				return true
			}
		} else if p == e || strings.HasPrefix(p, e+"?") {
			return true
		}
	}
	return false
}

// serveWebDeception handles the robots.txt / security.txt / sitemap.xml trio and
// the bait-path / sitemap-page probes. It returns the response banner to send
// (and sets res meta/anomalies); an empty return means "not a web-deception
// path — fall through to normal routing". When a sitemap page is requested with
// the tarpit on, it writes the response slowly itself and returns sentinelSlow
// so the caller skips its own write.
const sentinelHandled = "\x00wd-handled"

func serveWebDeception(conn net.Conn, wd config.WebDeception, method, path, server string, res *Result) string {
	if !wd.On() || method != "GET" {
		return ""
	}
	switch path {
	case "/robots.txt":
		res.Meta["web_deception"] = "robots.txt"
		return renderHTTPResponse(server, 200, "text/plain; charset=utf-8", robotsTxt(wd.Disallow()))
	case "/.well-known/security.txt", "/security.txt":
		res.Meta["web_deception"] = "security.txt"
		return renderHTTPResponse(server, 200, "text/plain; charset=utf-8",
			securityTxt(wd.Contacts(), wd.SecurityPolicyURL, wd.SecurityExpires))
	case "/sitemap.xml":
		res.Meta["web_deception"] = "sitemap.xml"
		return renderHTTPResponse(server, 200, "application/xml; charset=utf-8", sitemapXML(wd.Pages()))
	}

	// Probing a robots.txt Disallow entry: classic "read robots, hit the
	// forbidden paths" recon. Flag it, then serve a 403 so the path looks real.
	if matchesDecoyPath(path, wd.Disallow()) {
		flagAnomaly(res, "robots-honeypot-access")
		res.Meta["robots_disallowed_path"] = safe.SanitizeForLog(path)
		return renderHTTPResponse(server, 403, "text/html; charset=utf-8",
			"<html><head><title>403 Forbidden</title></head><body><h1>Forbidden</h1></body></html>")
	}

	// A sitemap-listed fake page: flag, then serve slowly to waste crawler time.
	if matchesDecoyPath(path, wd.Pages()) {
		flagAnomaly(res, "sitemap-honeypot-access")
		res.Meta["sitemap_page"] = safe.SanitizeForLog(path)
		body := sitemapPageHTML(path)
		resp := renderHTTPResponse(server, 200, "text/html; charset=utf-8", body)
		if wd.TarpitOn() {
			res.Meta["sitemap_tarpit_ms"] = int(wd.ByteInterval() / time.Millisecond)
			serveSlow(conn, resp, wd.ByteInterval())
			res.BannerSent = resp
			return sentinelHandled
		}
		return resp
	}
	return ""
}

// serveSlow writes an HTTP response in ~16 chunks with a delay between each, so
// a crawler stalls on the page. Bounded so a worker is never tied up for long;
// stops early if the peer goes away.
func serveSlow(conn net.Conn, resp string, interval time.Duration) {
	const chunks = 16
	n := len(resp)
	if n == 0 {
		return
	}
	sz := (n + chunks - 1) / chunks
	if sz < 1 {
		sz = 1
	}
	for i := 0; i < n; i += sz {
		end := i + sz
		if end > n {
			end = n
		}
		if _, err := conn.Write([]byte(resp[i:end])); err != nil {
			return
		}
		if end < n {
			time.Sleep(interval)
		}
	}
}
