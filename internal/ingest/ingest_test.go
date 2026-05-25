package ingest

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/rom/tarpit-honeypot/internal/event"
	"github.com/rom/tarpit-honeypot/internal/forward"
)

func batch(ids ...string) []byte {
	var evs []*event.Event
	for _, id := range ids {
		evs = append(evs, &event.Event{ID: id, SensorID: "depA", Severity: event.SeverityHigh, RuleID: "listener:http"})
	}
	b, _ := forward.EncodeBatch(evs, "child")
	return b
}

func newTestServer(t *testing.T, cfg Config) (*httptest.Server, *recorder) {
	t.Helper()
	rec := &recorder{}
	h := New(cfg, rec.sink)
	srv := httptest.NewServer(h.Mux())
	t.Cleanup(srv.Close)
	return srv, rec
}

type recorder struct {
	mu  sync.Mutex
	got []*event.Event
}

func (r *recorder) sink(evs []*event.Event) (int, int, int) {
	r.mu.Lock()
	r.got = append(r.got, evs...)
	r.mu.Unlock()
	return len(evs), 0, 0
}

func post(t *testing.T, url, token, sig string, body []byte) *http.Response {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, url+"/ingest", bytes.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if sig != "" {
		req.Header.Set("X-Tarpit-Signature", sig)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestIngestAcceptsAuthedBatch(t *testing.T) {
	secret := []byte("s3cr3t")
	srv, rec := newTestServer(t, Config{Token: "tok", HMACSecret: secret})
	body := batch("e1", "e2")
	resp := post(t, srv.URL, "tok", "sha256="+forward.SignBody(secret, body), body)
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d; want 200", resp.StatusCode)
	}
	if len(rec.got) != 2 || rec.got[0].ID != "e1" {
		t.Errorf("sink got %d events; want 2 (e1,e2)", len(rec.got))
	}
}

func TestIngestRejectsBadAuth(t *testing.T) {
	srv, rec := newTestServer(t, Config{Token: "tok"})
	body := batch("e1")
	for _, tc := range []struct {
		name, token string
	}{{"no-token", ""}, {"wrong-token", "nope"}} {
		resp := post(t, srv.URL, tc.token, "", body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s: status = %d; want 401", tc.name, resp.StatusCode)
		}
	}
	if len(rec.got) != 0 {
		t.Errorf("no events should be admitted on bad auth; got %d", len(rec.got))
	}
}

func TestIngestRejectsBadHMAC(t *testing.T) {
	secret := []byte("s3cr3t")
	srv, rec := newTestServer(t, Config{Token: "tok", HMACSecret: secret})
	body := batch("e1")
	resp := post(t, srv.URL, "tok", "sha256=deadbeef", body) // wrong sig
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d; want 401 on bad signature", resp.StatusCode)
	}
	if len(rec.got) != 0 {
		t.Error("no events should be admitted on bad signature")
	}
}

func TestIngestMethodAndHealth(t *testing.T) {
	srv, _ := newTestServer(t, Config{Token: "tok"})
	resp, _ := http.Get(srv.URL + "/ingest")
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("GET /ingest = %d; want 405", resp.StatusCode)
	}
	hz, _ := http.Get(srv.URL + "/healthz")
	hz.Body.Close()
	if hz.StatusCode != 200 {
		t.Errorf("GET /healthz = %d; want 200", hz.StatusCode)
	}
}

func TestIngestRejectsOversize(t *testing.T) {
	srv, _ := newTestServer(t, Config{Token: "tok", MaxBody: 8})
	resp := post(t, srv.URL, "tok", "", batch("e1", "e2", "e3"))
	resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Errorf("status = %d; want 413", resp.StatusCode)
	}
}
