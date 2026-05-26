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
		if !strings.Contains(sc, themeCookieName+"="+id) {
			t.Errorf("theme=%s: Set-Cookie = %q; want %s=%s", id, sc, themeCookieName, id)
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
	if !strings.Contains(sc, themeCookieName+"=;") && !strings.Contains(sc, "Max-Age=0") {
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
	r.AddCookie(&http.Cookie{Name: themeCookieName, Value: "nord"})
	if got := currentTheme(r); got != "nord" {
		t.Errorf("nord cookie -> nord; got %q", got)
	}
	r2 := httptest.NewRequest(http.MethodGet, "/", nil)
	r2.AddCookie(&http.Cookie{Name: themeCookieName, Value: "evil"})
	if got := currentTheme(r2); got != "default" {
		t.Errorf("unknown cookie -> default; got %q", got)
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
