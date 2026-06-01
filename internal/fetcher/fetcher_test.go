package fetcher

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/egress"
)

// allowlistedPolicy returns an egress policy that permits exactly the given
// host:port (so the fetcher can dial the test server but nothing else).
func allowlistedPolicy(dest string) *egress.Policy {
	p := egress.New()
	p.Allow(dest)
	return p
}

func TestFetchStoresDownloadedArtifact(t *testing.T) {
	const elf = "\x7fELF\x02\x01\x01\x00payload-bytes-here-pretend-binary"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(elf))
	}))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")

	f := New(allowlistedPolicy(host), 5*time.Second, 0)
	art, ok := f.Fetch(context.Background(), srv.URL+"/x.bin")
	if !ok {
		t.Fatal("expected a fetched artifact")
	}
	if art.Size != len(elf) {
		t.Errorf("artifact size = %d, want %d", art.Size, len(elf))
	}
	if art.SHA256 == "" {
		t.Errorf("artifact missing sha256")
	}
	// An ELF magic should classify as an executable, not a generic download.
	if art.Kind != "elf" {
		t.Errorf("kind = %q, want elf", art.Kind)
	}
}

func TestFetchRespectsEgressAllowlist(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("data"))
	}))
	defer srv.Close()
	// Policy that allowlists a DIFFERENT host → the fetch to srv must be denied.
	f := New(allowlistedPolicy("203.0.113.1:9"), 5*time.Second, 0)
	if _, ok := f.Fetch(context.Background(), srv.URL+"/x"); ok {
		t.Error("fetch to a non-allowlisted host should be denied by egress")
	}
}

func TestFetchCapsSize(t *testing.T) {
	big := strings.Repeat("A", 1<<20) // 1 MiB body
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, big)
	}))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	f := New(allowlistedPolicy(host), 5*time.Second, 1024) // cap at 1 KiB
	art, ok := f.Fetch(context.Background(), srv.URL+"/big")
	if !ok {
		t.Fatal("expected an artifact")
	}
	if art.Size > 1024 {
		t.Errorf("download not capped: size=%d, want <=1024", art.Size)
	}
}

func TestFetchRejectsNonHTTP(t *testing.T) {
	f := New(allowlistedPolicy("x:1"), time.Second, 0)
	for _, u := range []string{"ftp://x/y", "file:///etc/passwd", "gopher://x", "not a url", ""} {
		if _, ok := f.Fetch(context.Background(), u); ok {
			t.Errorf("non-http(s) URL %q should be rejected", u)
		}
	}
}

func TestNilFetcherDisabled(t *testing.T) {
	var f *Fetcher
	if _, ok := f.Fetch(context.Background(), "http://x/y"); ok {
		t.Error("nil fetcher must be a no-op")
	}
	// A fetcher built with a nil policy is fail-closed too.
	f2 := New(nil, time.Second, 0)
	if _, ok := f2.Fetch(context.Background(), "http://x/y"); ok {
		t.Error("fetcher with nil policy must refuse every fetch")
	}
}
