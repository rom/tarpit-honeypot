package misp

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/rom/tarpit-honeypot/internal/intel"
)

func TestAttributeMapping(t *testing.T) {
	cases := []struct {
		ioc       intel.IOC
		wantType  string
		wantValue string
	}{
		{intel.IOC{Kind: "ip", Value: "1.2.3.4"}, "ip-src", "1.2.3.4"},
		{intel.IOC{Kind: "asn", Value: "AS64500"}, "AS", "AS64500"},
		{intel.IOC{Kind: "fingerprint", Value: "ja3:abc"}, "ja3-fingerprint-md5", "abc"},
		{intel.IOC{Kind: "fingerprint", Value: "hassh:def"}, "hassh-md5", "def"},
	}
	for _, c := range cases {
		a, ok := attribute(c.ioc)
		if !ok {
			t.Errorf("%+v: not mapped", c.ioc)
			continue
		}
		if a["type"] != c.wantType || a["value"] != c.wantValue {
			t.Errorf("%+v -> type=%v value=%v; want %s/%s", c.ioc, a["type"], a["value"], c.wantType, c.wantValue)
		}
	}
}

func TestPusherDelta(t *testing.T) {
	var mu sync.Mutex
	var posts int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		mu.Lock()
		posts++
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	iocs := []intel.IOC{{Kind: "ip", Value: "1.1.1.1", Reason: "x"}}
	p := NewPusher(Config{URL: srv.URL, Key: "k", Client: srv.Client()}, func() []intel.IOC { return iocs })
	ctx := context.Background()

	p.once(ctx) // first push: 1 new attribute
	p.once(ctx) // nothing new -> no push (delta)
	mu.Lock()
	n := posts
	mu.Unlock()
	if n != 1 {
		t.Fatalf("posts = %d; want 1 (delta should suppress the unchanged push)", n)
	}

	iocs = append(iocs, intel.IOC{Kind: "asn", Value: "AS5", Reason: "y"})
	p.once(ctx) // a new IOC -> one more push
	mu.Lock()
	n = posts
	mu.Unlock()
	if n != 2 {
		t.Errorf("posts = %d; want 2 after a new IOC appeared", n)
	}
}
