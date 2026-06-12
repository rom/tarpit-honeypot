package ui

import (
	"net"
	"net/http"
	"strings"
)

// Theme is one entry in the in-product theme catalog: an id (used as both the
// cookie value and the CSS class suffix), a human-readable label, a short
// description for the picker, and a sample swatch hex for the selector UI.
type Theme struct {
	ID, Label, Desc, Swatch string
}

// themes is the full catalog: a `default` (light, no class on <html>) plus
// four alternative themes whose CSS overrides live under :root.theme-<id>. The
// id is restricted to a safe charset (lowercase letters, digits, hyphen) so
// the cookie value cannot inject anything into the bootstrap script's class
// string or the server-rendered selector links.
var themes = []Theme{
	{ID: "default", Label: "Default", Desc: "Light, gray surfaces.", Swatch: "#6b8fb5"},
	{ID: "dark", Label: "Dark", Desc: "Slate gray, light text.", Swatch: "#23262e"},
	{ID: "solarized-dark", Label: "Solarized Dark", Desc: "The classic solarized palette.", Swatch: "#073642"},
	{ID: "nord", Label: "Nord", Desc: "Cool, slightly desaturated.", Swatch: "#5e81ac"},
	{ID: "high-contrast", Label: "High contrast", Desc: "Pure black + vivid accents (accessibility).", Swatch: "#000000"},
	{ID: "cobalt", Label: "Cobalt", Desc: "Deep saturated blue, light text.", Swatch: "#0a1929"},
	{ID: "sepia", Label: "Sepia", Desc: "Warm parchment with brown accents.", Swatch: "#f6efd9"},
	{ID: "olive", Label: "Olive", Desc: "Olive drab, muted greens.", Swatch: "#494e36"},
}

// themeIDs is the set of valid theme ids, populated from themes for O(1)
// lookup.
var themeIDs = func() map[string]bool {
	m := make(map[string]bool, len(themes))
	for _, t := range themes {
		m[t.ID] = true
	}
	return m
}()

const (
	themeCookieBase = "tarpit_theme"
	themeMaxAge     = 365 * 24 * 60 * 60 // one year
	sizeCookieBase  = "tarpit_size"
)

// instancePort returns the port this UI is served on, read from the request's
// Host header — the one thing that distinguishes sibling instances on the same
// host. Cookies are scoped by host only (RFC 6265 ignores the port), so two
// instances on 127.0.0.1:8088 and :8089 would otherwise SHARE one theme/size
// cookie — change it in one and it changes in the other. Baking the port into
// the cookie NAME keeps each instance's preference separate even though the
// browser still delivers every sibling's cookie to all of them. Digits only (a
// cookie name must be an RFC token); "0" when there is no explicit port.
func instancePort(r *http.Request) string {
	if r == nil || r.Host == "" {
		return "0"
	}
	if _, port, err := net.SplitHostPort(r.Host); err == nil && port != "" {
		for _, c := range port {
			if c < '0' || c > '9' {
				return "0"
			}
		}
		return port
	}
	return "0"
}

// themeCookieName / sizeCookieName are the per-instance cookie names; the
// client (static/theme.js) builds the same names from location.port.
func themeCookieName(r *http.Request) string { return themeCookieBase + "_" + instancePort(r) }
func sizeCookieName(r *http.Request) string  { return sizeCookieBase + "_" + instancePort(r) }

// Size is one entry in the font-size scale catalog: an id (cookie value and
// CSS class suffix), a label and a sample px size for the picker. "normal" is
// the unmarked default — selecting it clears the cookie.
type Size struct {
	ID, Label, Sample string
}

// sizes is the full scale: a `normal` default plus four discrete steps. The
// CSS lives under :root.size-<id>; each id sets --font-size-base, which the
// rem-based stylesheet inherits from.
var sizes = []Size{
	{ID: "small", Label: "Small", Sample: "12px"},
	{ID: "normal", Label: "Normal", Sample: "14px"},
	{ID: "large", Label: "Large", Sample: "16px"},
	{ID: "xlarge", Label: "Extra large", Sample: "18px"},
	{ID: "xxlarge", Label: "XX-large", Sample: "20px"},
}

var sizeIDs = func() map[string]bool {
	m := make(map[string]bool, len(sizes))
	for _, s := range sizes {
		m[s.ID] = true
	}
	return m
}()

// handleTheme sets the tarpit_theme cookie from a validated ?t=<id> query
// parameter and redirects back to ?back=<path>. Idempotent and side-effect-
// free except for the cookie itself; safe-by-construction against header /
// open-redirect injection because both inputs are strictly validated.
func (s *Server) handleTheme(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("t")
	if !themeIDs[id] {
		http.Error(w, "unknown theme", http.StatusBadRequest)
		return
	}
	back := safeBackPath(r.URL.Query().Get("back"))
	cookie := &http.Cookie{
		Name:     themeCookieName(r),
		Value:    id,
		Path:     "/",
		MaxAge:   themeMaxAge,
		HttpOnly: false, // read by /static/theme.js
		SameSite: http.SameSiteLaxMode,
		Secure:   r.TLS != nil,
	}
	// Selecting "default" clears the cookie so :root inherits the unthemed
	// defaults without a stale class lingering on <html>.
	if id == "default" {
		cookie.Value = ""
		cookie.MaxAge = -1
	}
	http.SetCookie(w, cookie)
	http.Redirect(w, r, back, http.StatusSeeOther)
}

// safeBackPath validates the ?back= redirect target: must be a same-origin
// path (starts with one "/" and is not "//", which browsers parse as a
// protocol-relative URL to another origin). Falls back to /config so the
// theme picker on the config page round-trips cleanly.
func safeBackPath(s string) string {
	if !strings.HasPrefix(s, "/") || strings.HasPrefix(s, "//") || strings.HasPrefix(s, "/\\") {
		return "/config"
	}
	// Defense in depth: refuse anything containing a CR/LF that could split
	// the Location header.
	if strings.ContainsAny(s, "\r\n") {
		return "/config"
	}
	return s
}

// currentTheme returns the theme id from the request's cookie, or "default"
// when absent / unknown. Used by the config-page selector to mark the active
// link.
func currentTheme(r *http.Request) string {
	c, err := r.Cookie(themeCookieName(r))
	if err != nil || c.Value == "" || !themeIDs[c.Value] {
		return "default"
	}
	return c.Value
}

// themeLinks returns the catalog enriched with rendering hints for the picker
// template (the "active" flag and the per-theme href that round-trips back to
// the page that opened the picker).
type themeLink struct {
	Theme
	Active bool
	Href   string
}

func themePickerLinks(active, back string) []themeLink {
	out := make([]themeLink, 0, len(themes))
	for _, t := range themes {
		out = append(out, themeLink{
			Theme:  t,
			Active: t.ID == active,
			Href:   "/theme?t=" + t.ID + "&back=" + back,
		})
	}
	return out
}

// handleSize sets the tarpit_size cookie from a validated ?s=<id> query
// parameter and redirects back to a validated same-origin ?back=<path>. The
// "normal" id clears the cookie (so :root inherits the unmarked default).
// Mirrors handleTheme — same allowlist + redirect-guard model.
func (s *Server) handleSize(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("s")
	if !sizeIDs[id] {
		http.Error(w, "unknown size", http.StatusBadRequest)
		return
	}
	back := safeBackPath(r.URL.Query().Get("back"))
	cookie := &http.Cookie{
		Name:     sizeCookieName(r),
		Value:    id,
		Path:     "/",
		MaxAge:   themeMaxAge,
		HttpOnly: false,
		SameSite: http.SameSiteLaxMode,
		Secure:   r.TLS != nil,
	}
	if id == "normal" {
		cookie.Value = ""
		cookie.MaxAge = -1
	}
	http.SetCookie(w, cookie)
	http.Redirect(w, r, back, http.StatusSeeOther)
}

// currentSize returns the size id from the request's cookie, or "normal" when
// absent / unknown — used to mark the active link in the picker.
func currentSize(r *http.Request) string {
	c, err := r.Cookie(sizeCookieName(r))
	if err != nil || c.Value == "" || !sizeIDs[c.Value] {
		return "normal"
	}
	return c.Value
}

// sizeLink is a Size enriched with rendering hints for the picker template.
type sizeLink struct {
	Size
	Active bool
	Href   string
}

func sizePickerLinks(active, back string) []sizeLink {
	out := make([]sizeLink, 0, len(sizes))
	for _, sz := range sizes {
		out = append(out, sizeLink{
			Size:   sz,
			Active: sz.ID == active,
			Href:   "/size?s=" + sz.ID + "&back=" + back,
		})
	}
	return out
}
