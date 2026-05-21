package ui

import (
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/rom/tarpit-honeypot/internal/config"
)

// fakeDeviceActions records the calls the UI makes.
type fakeDeviceActions struct {
	deleted, allowed []string
	ok               bool
}

func (f *fakeDeviceActions) Delete(key string) bool { f.deleted = append(f.deleted, key); return f.ok }
func (f *fakeDeviceActions) Allow(key string) bool  { f.allowed = append(f.allowed, key); return f.ok }

func newActionServer(t *testing.T, flag bool, token string) (*Server, *fakeDeviceActions) {
	t.Helper()
	fa := &fakeDeviceActions{ok: true}
	s := &Server{
		authToken:     token,
		deviceActions: fa,
		fullConfig:    &config.Config{UI: config.UI{AllowDeviceActions: flag}},
	}
	return s, fa
}

func postAction(s *Server, form url.Values) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/devices/action", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	s.handleDeviceAction(w, req)
	return w
}

func TestDeviceActionGatingDisabled(t *testing.T) {
	// Flag off → 403 even with a valid token.
	s, fa := newActionServer(t, false, "tok")
	w := postAction(s, url.Values{"token": {"tok"}, "action": {"delete"}, "key": {"1.2.3.4"}})
	if w.Code != 403 {
		t.Errorf("flag off: code=%d want 403", w.Code)
	}
	if len(fa.deleted) != 0 {
		t.Errorf("flag off should not call Delete: %v", fa.deleted)
	}
}

func TestDeviceActionRequiresToken(t *testing.T) {
	// Flag on, token configured, but wrong token in the form → 401.
	s, fa := newActionServer(t, true, "right")
	w := postAction(s, url.Values{"token": {"wrong"}, "action": {"delete"}, "key": {"1.2.3.4"}})
	if w.Code != 401 {
		t.Errorf("bad token: code=%d want 401", w.Code)
	}
	if len(fa.deleted) != 0 {
		t.Errorf("bad token should not call Delete: %v", fa.deleted)
	}
}

func TestDeviceActionNoTokenConfigured(t *testing.T) {
	// Flag on but no auth token configured → actions disabled (403).
	s, _ := newActionServer(t, true, "")
	w := postAction(s, url.Values{"token": {""}, "action": {"delete"}, "key": {"1.2.3.4"}})
	if w.Code != 403 {
		t.Errorf("no token configured: code=%d want 403", w.Code)
	}
}

func TestDeviceActionSucceeds(t *testing.T) {
	s, fa := newActionServer(t, true, "tok")
	w := postAction(s, url.Values{"token": {"tok"}, "action": {"allow"}, "key": {"aa:bb:cc:dd:ee:ff"}})
	if w.Code != 303 { // redirect after success
		t.Errorf("success: code=%d want 303", w.Code)
	}
	if len(fa.allowed) != 1 || fa.allowed[0] != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("Allow not called with key: %v", fa.allowed)
	}

	w = postAction(s, url.Values{"token": {"tok"}, "action": {"delete"}, "key": {"1.2.3.4"}})
	if w.Code != 303 || len(fa.deleted) != 1 || fa.deleted[0] != "1.2.3.4" {
		t.Errorf("delete path: code=%d deleted=%v", w.Code, fa.deleted)
	}
}

func TestDeviceActionGetRejected(t *testing.T) {
	s, _ := newActionServer(t, true, "tok")
	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/devices/action", nil)
	s.handleDeviceAction(w, req)
	if w.Code != 405 {
		t.Errorf("GET should be 405; got %d", w.Code)
	}
}
