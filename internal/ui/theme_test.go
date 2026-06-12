package ui

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestSafeBackPath(t *testing.T) {
	cases := []struct{ in, want string }{
		{"/events", "/events"},
		{"/events?source=1.2.3.4", "/events?source=1.2.3.4"},
		{"/", "/"},
		{"", "/config"},                           // empty -> default
		{"//evil.example.com/x", "/config"},       // protocol-relative
		{"/\\evil.example.com/x", "/config"},      // backslash variant
		{"https://evil.example.com/x", "/config"}, // absolute external URL
		{"javascript:alert(1)", "/config"},        // non-path scheme
		{"/events\r\nSet-Cookie: x=y", "/config"}, // CRLF header split
	}
	for _, c := range cases {
		if got := safeBackPath(c.in); got != c.want {
			t.Errorf("safeBackPath(%q) = %q; want %q", c.in, got, c.want)
		}
	}
}

func TestHandleThemeSetsCookieAndRedirects(t *testing.T) {
	s := &Server{}
	for _, id := range []string{"dark", "solarized-dark", "nord", "high-contrast"} {
		req := httptest.NewRequest(http.MethodGet, "/theme?t="+id+"&back=/events", nil)
		w := httptest.NewRecorder()
		s.handleTheme(w, req)
		if w.Code != http.StatusSeeOther {
			t.Errorf("theme=%s: status = %d; want 303", id, w.Code)
		}
		if got := w.Header().Get("Location"); got != "/events" {
			t.Errorf("theme=%s: Location = %q; want /events", id, got)
		}
		sc := w.Header().Get("Set-Cookie")
		name := themeCookieName(req)
		if !strings.Contains(sc, name+"="+id) {
			t.Errorf("theme=%s: Set-Cookie = %q; want %s=%s", id, sc, name, id)
		}
		if !strings.Contains(sc, "SameSite=Lax") {
			t.Errorf("theme=%s: missing SameSite=Lax: %q", id, sc)
		}
		if !strings.Contains(sc, "Path=/") {
			t.Errorf("theme=%s: missing Path=/: %q", id, sc)
		}
	}
}

func TestHandleThemeRejectsUnknown(t *testing.T) {
	s := &Server{}
	for _, id := range []string{"", "evil", "; rm -rf", "default-x", "DARK", "../etc", `<script>`} {
		req := httptest.NewRequest(http.MethodGet, "/theme?t="+url.QueryEscape(id), nil)
		w := httptest.NewRecorder()
		s.handleTheme(w, req)
		if w.Code != http.StatusBadRequest {
			t.Errorf("theme=%q: status = %d; want 400", id, w.Code)
		}
		if w.Header().Get("Set-Cookie") != "" {
			t.Errorf("theme=%q: unknown theme should not set a cookie", id)
		}
	}
}

func TestHandleThemeDefaultClearsCookie(t *testing.T) {
	s := &Server{}
	req := httptest.NewRequest(http.MethodGet, "/theme?t=default&back=/", nil)
	w := httptest.NewRecorder()
	s.handleTheme(w, req)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("status = %d; want 303", w.Code)
	}
	sc := w.Header().Get("Set-Cookie")
	if !strings.Contains(sc, themeCookieName(req)+"=;") && !strings.Contains(sc, "Max-Age=0") {
		t.Errorf("default theme should clear the cookie; got %q", sc)
	}
}

func TestHandleThemeOpenRedirectGuard(t *testing.T) {
	s := &Server{}
	req := httptest.NewRequest(http.MethodGet, "/theme?t=dark&back=//evil.example.com", nil)
	w := httptest.NewRecorder()
	s.handleTheme(w, req)
	if got := w.Header().Get("Location"); got != "/config" {
		t.Errorf("open-redirect back=//... should fall back to /config; got %q", got)
	}
}

func TestCurrentTheme(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	if got := currentTheme(r); got != "default" {
		t.Errorf("no cookie -> default; got %q", got)
	}
	r.AddCookie(&http.Cookie{Name: themeCookieName(r), Value: "nord"})
	if got := currentTheme(r); got != "nord" {
		t.Errorf("nord cookie -> nord; got %q", got)
	}
	r2 := httptest.NewRequest(http.MethodGet, "/", nil)
	r2.AddCookie(&http.Cookie{Name: themeCookieName(r2), Value: "evil"})
	if got := currentTheme(r2); got != "default" {
		t.Errorf("unknown cookie -> default; got %q", got)
	}
}

// Sibling instances on the same host (different UI ports) must not share a
// theme/size cookie — the reported "change it in one, it changes in the other"
// leak. Cookies ignore the port, so we discriminate by baking the port into the
// cookie name.
func TestThemeCookieIsPerInstance(t *testing.T) {
	r88 := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8088/", nil)
	r89 := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8089/", nil)
	if n88, n89 := themeCookieName(r88), themeCookieName(r89); n88 == n89 {
		t.Fatalf("per-instance cookie names collide: %q", n88)
	} else if n88 != "tarpit_theme_8088" || n89 != "tarpit_theme_8089" {
		t.Fatalf("unexpected names: %q / %q", n88, n89)
	}
	// The browser delivers :8088's cookie to :8089 (it ignores the port); :8089
	// must still NOT pick up :8088's theme.
	r89.AddCookie(&http.Cookie{Name: themeCookieName(r88), Value: "nord"})
	if got := currentTheme(r89); got != "default" {
		t.Errorf(":8089 read :8088's theme (%q) — cookies still leak", got)
	}
	// :8089 reading its own cookie still works.
	own := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8089/", nil)
	own.AddCookie(&http.Cookie{Name: themeCookieName(own), Value: "dark"})
	if got := currentTheme(own); got != "dark" {
		t.Errorf(":8089 own theme = %q; want dark", got)
	}
	// No explicit port collapses to a stable "0" suffix on both sides.
	if n := themeCookieName(httptest.NewRequest(http.MethodGet, "/", nil)); n != "tarpit_theme_0" {
		t.Errorf("no-port name = %q; want tarpit_theme_0", n)
	}
}

func TestThemePickerLinks(t *testing.T) {
	links := themePickerLinks("dark", "/events")
	if len(links) != len(themes) {
		t.Fatalf("links = %d; want %d", len(links), len(themes))
	}
	activeCount := 0
	for _, l := range links {
		if l.Active {
			activeCount++
			if l.ID != "dark" {
				t.Errorf("wrong active theme: %q", l.ID)
			}
		}
		if !strings.HasPrefix(l.Href, "/theme?t="+l.ID+"&back=/events") {
			t.Errorf("link %q has bad href: %q", l.ID, l.Href)
		}
	}
	if activeCount != 1 {
		t.Errorf("active count = %d; want 1", activeCount)
	}
}

func TestHandleSizeSetsCookieAndRedirects(t *testing.T) {
	s := &Server{}
	for _, id := range []string{"small", "large", "xlarge", "xxlarge"} {
		req := httptest.NewRequest(http.MethodGet, "/size?s="+id+"&back=/events", nil)
		w := httptest.NewRecorder()
		s.handleSize(w, req)
		if w.Code != http.StatusSeeOther {
			t.Errorf("size=%s: status = %d; want 303", id, w.Code)
		}
		sc := w.Header().Get("Set-Cookie")
		name := sizeCookieName(req)
		if !strings.Contains(sc, name+"="+id) {
			t.Errorf("size=%s: Set-Cookie = %q; want %s=%s", id, sc, name, id)
		}
		if !strings.Contains(sc, "SameSite=Lax") {
			t.Errorf("size=%s: missing SameSite=Lax: %q", id, sc)
		}
	}
}

func TestHandleSizeRejectsUnknown(t *testing.T) {
	s := &Server{}
	for _, id := range []string{"", "huge", "; evil", "DEFAULT", "../etc"} {
		req := httptest.NewRequest(http.MethodGet, "/size?s="+url.QueryEscape(id), nil)
		w := httptest.NewRecorder()
		s.handleSize(w, req)
		if w.Code != http.StatusBadRequest {
			t.Errorf("size=%q: status = %d; want 400", id, w.Code)
		}
		if w.Header().Get("Set-Cookie") != "" {
			t.Errorf("size=%q: unknown size should not set a cookie", id)
		}
	}
}

func TestHandleSizeNormalClearsCookie(t *testing.T) {
	s := &Server{}
	req := httptest.NewRequest(http.MethodGet, "/size?s=normal&back=/", nil)
	w := httptest.NewRecorder()
	s.handleSize(w, req)
	sc := w.Header().Get("Set-Cookie")
	if !strings.Contains(sc, sizeCookieName(req)+"=;") && !strings.Contains(sc, "Max-Age=0") {
		t.Errorf("normal size should clear the cookie; got %q", sc)
	}
}

func TestCurrentSize(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	if got := currentSize(r); got != "normal" {
		t.Errorf("no cookie -> normal; got %q", got)
	}
	r.AddCookie(&http.Cookie{Name: sizeCookieName(r), Value: "large"})
	if got := currentSize(r); got != "large" {
		t.Errorf("large cookie -> large; got %q", got)
	}
	r2 := httptest.NewRequest(http.MethodGet, "/", nil)
	r2.AddCookie(&http.Cookie{Name: sizeCookieName(r2), Value: "evil"})
	if got := currentSize(r2); got != "normal" {
		t.Errorf("unknown cookie -> normal; got %q", got)
	}
}

func TestHandleFavicon(t *testing.T) {
	s := &Server{}
	req := httptest.NewRequest(http.MethodGet, "/favicon.ico", nil)
	w := httptest.NewRecorder()
	s.handleFavicon(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d; want 200", w.Code)
	}
	if got := w.Header().Get("Content-Type"); got != "image/x-icon" {
		t.Errorf("Content-Type = %q; want image/x-icon", got)
	}
	body := w.Body.Bytes()
	if len(body) < 100 {
		t.Errorf("body too small: %d bytes", len(body))
	}
	// ICO magic: 00 00 01 00 (reserved + type=1)
	if len(body) < 4 || body[0] != 0 || body[1] != 0 || body[2] != 1 || body[3] != 0 {
		t.Errorf("bad ICO magic: % x", body[:4])
	}
}

func TestSizePickerLinks(t *testing.T) {
	links := sizePickerLinks("large", "/config")
	if len(links) != len(sizes) {
		t.Fatalf("links = %d; want %d", len(links), len(sizes))
	}
	active := 0
	for _, l := range links {
		if l.Active {
			active++
			if l.ID != "large" {
				t.Errorf("wrong active size: %q", l.ID)
			}
		}
		if !strings.HasPrefix(l.Href, "/size?s="+l.ID+"&back=/config") {
			t.Errorf("link %q has bad href: %q", l.ID, l.Href)
		}
	}
	if active != 1 {
		t.Errorf("active count = %d; want 1", active)
	}
}
