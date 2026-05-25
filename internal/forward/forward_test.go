package forward

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/event"
)

type recvd struct {
	body  []byte
	auth  string
	sig   string
	node  string
	count string
	ctype string
}

// captureServer records each ingest POST and returns status(n) for the n-th
// request (1-indexed).
func captureServer(t *testing.T, got chan<- recvd, status func(n int) int) *httptest.Server {
	t.Helper()
	var n int32
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		i := int(atomic.AddInt32(&n, 1))
		b, _ := readAll(r)
		got <- recvd{
			body: b, auth: r.Header.Get("Authorization"), sig: r.Header.Get("X-Tarpit-Signature"),
			node: r.Header.Get("X-Tarpit-Node"), count: r.Header.Get("X-Tarpit-Batch-Count"),
			ctype: r.Header.Get("Content-Type"),
		}
		w.WriteHeader(status(i))
	}))
}

func readAll(r *http.Request) ([]byte, error) {
	defer r.Body.Close()
	buf := make([]byte, 0, 4096)
	tmp := make([]byte, 4096)
	for {
		n, err := r.Body.Read(tmp)
		buf = append(buf, tmp[:n]...)
		if err != nil {
			return buf, nil
		}
	}
}

func ev(id string, sev event.Severity) *event.Event {
	return &event.Event{ID: id, SensorID: "depA", Sensor: "sensorA", Severity: sev,
		RuleID: "listener:http", Source: event.Endpoint{IP: "203.0.113.9"}, Meta: map[string]any{"asn": "AS64500"}}
}

func TestCodecRoundTrip(t *testing.T) {
	in := []*event.Event{ev("e1", event.SeverityHigh), ev("e2", event.SeverityLow)}
	in[0].Hops = []string{"sensorA"}
	body, err := EncodeBatch(in, "agg1")
	if err != nil {
		t.Fatal(err)
	}
	out, err := DecodeBatch(bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 2 {
		t.Fatalf("decoded %d events; want 2", len(out))
	}
	if out[0].ID != "e1" || out[0].SensorID != "depA" || out[0].RuleID != "listener:http" || out[0].Source.IP != "203.0.113.9" {
		t.Errorf("fields lost: %+v", out[0])
	}
	if out[0].Severity != event.SeverityHigh {
		t.Errorf("severity lost: %v", out[0].Severity)
	}
	// Hops: existing chain preserved + the encoder node appended.
	if len(out[0].Hops) != 2 || out[0].Hops[0] != "sensorA" || out[0].Hops[1] != "agg1" {
		t.Errorf("hops wrong: %v", out[0].Hops)
	}
	if out[1].Hops[len(out[1].Hops)-1] != "agg1" {
		t.Errorf("second event not stamped: %v", out[1].Hops)
	}
}

func TestEncodeDoesNotMutateSource(t *testing.T) {
	e := ev("e1", event.SeverityHigh)
	if _, err := EncodeBatch([]*event.Event{e}, "agg1"); err != nil {
		t.Fatal(err)
	}
	if len(e.Hops) != 0 {
		t.Errorf("EncodeBatch mutated the shared event's Hops: %v", e.Hops)
	}
}

func TestForwarderDelivers(t *testing.T) {
	got := make(chan recvd, 4)
	srv := captureServer(t, got, func(int) int { return 200 })
	defer srv.Close()

	f := NewForwarder(Target{ID: "t1", URL: srv.URL, NodeID: "sensorA", Token: "tok",
		HMACSecret: []byte("secret"), MaxBatch: 2, MaxAge: 50 * time.Millisecond})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go f.Run(ctx)

	f.Enqueue(ev("e1", event.SeverityHigh))
	f.Enqueue(ev("e2", event.SeverityHigh))

	r := waitRecv(t, got)
	if r.count != "2" || r.ctype != "application/x-ndjson" {
		t.Errorf("batch headers wrong: count=%q ctype=%q", r.count, r.ctype)
	}
	if r.auth != "Bearer tok" || r.node != "sensorA" {
		t.Errorf("auth/node header wrong: %q / %q", r.auth, r.node)
	}
	if !VerifySignature([]byte("secret"), r.body, r.sig) {
		t.Errorf("HMAC signature did not verify: %q", r.sig)
	}
	evs, err := DecodeBatch(bytes.NewReader(r.body))
	if err != nil || len(evs) != 2 {
		t.Fatalf("decode batch: %d events, err=%v", len(evs), err)
	}
	if evs[0].Hops[len(evs[0].Hops)-1] != "sensorA" {
		t.Errorf("forwarded event not stamped with node id: %v", evs[0].Hops)
	}
	pollSent(t, f, 2) // POST completes shortly after the server receives it
}

func TestForwarderRollup(t *testing.T) {
	got := make(chan recvd, 4)
	srv := captureServer(t, got, func(int) int { return 200 })
	defer srv.Close()

	f := NewForwarder(Target{ID: "r1", URL: srv.URL, NodeID: "aggA",
		Mode: "rollup", RollupInterval: 30 * time.Millisecond})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go f.Run(ctx)

	f.Enqueue(ev("e1", event.SeverityHigh)) // source 203.0.113.9
	f.Enqueue(ev("e2", event.SeverityLow))
	f.Enqueue(&event.Event{ID: "e3", SensorID: "depA", Severity: event.SeverityCritical,
		RuleID: "cve:CVE-2021-44228", Source: event.Endpoint{IP: "198.51.100.7"},
		Meta: map[string]any{"ja3": "abc"}})

	r := waitRecv(t, got)
	evs, err := DecodeBatch(bytes.NewReader(r.body))
	if err != nil || len(evs) != 1 {
		t.Fatalf("rollup batch: %d events, err=%v", len(evs), err)
	}
	re := evs[0]
	if re.RuleID != "fleet:rollup" {
		t.Fatalf("rule_id = %q; want fleet:rollup", re.RuleID)
	}
	if tot, _ := re.Meta["total"].(float64); int(tot) != 3 {
		t.Errorf("total = %v; want 3", re.Meta["total"])
	}
	if ds, _ := re.Meta["distinct_sources"].(float64); int(ds) != 2 {
		t.Errorf("distinct_sources = %v; want 2", re.Meta["distinct_sources"])
	}
	if re.Severity != event.SeverityCritical { // max severity folded
		t.Errorf("severity = %v; want critical", re.Severity)
	}
	pollSent(t, f, 1)
}

func TestForwarderRetries(t *testing.T) {
	got := make(chan recvd, 8)
	// fail the first two attempts, then accept.
	srv := captureServer(t, got, func(n int) int {
		if n < 3 {
			return 500
		}
		return 200
	})
	defer srv.Close()

	f := NewForwarder(Target{ID: "t1", URL: srv.URL, NodeID: "s", MaxBatch: 1, MaxAge: time.Hour})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go f.Run(ctx)
	f.Enqueue(ev("e1", event.SeverityHigh))

	// three requests should arrive (2 failures + 1 success).
	for i := 0; i < 3; i++ {
		waitRecv(t, got)
	}
	pollSent(t, f, 1)
	if _, _, failed := f.Stats(); failed != 0 {
		t.Errorf("after retry: failed=%d; want 0", failed)
	}
}

// pollSent waits for the forwarder's sent counter to reach want.
func pollSent(t *testing.T, f *Forwarder, want int64) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if sent, _, _ := f.Stats(); sent >= want {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	sent, _, _ := f.Stats()
	t.Fatalf("sent = %d; want %d", sent, want)
}

func TestForwarderMinSeverity(t *testing.T) {
	got := make(chan recvd, 4)
	srv := captureServer(t, got, func(int) int { return 200 })
	defer srv.Close()
	f := NewForwarder(Target{ID: "t1", URL: srv.URL, NodeID: "s", MinSeverity: event.SeverityHigh, MaxBatch: 1, MaxAge: 30 * time.Millisecond})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go f.Run(ctx)
	f.Enqueue(ev("low", event.SeverityLow)) // filtered
	f.Enqueue(ev("high", event.SeverityHigh))
	r := waitRecv(t, got)
	evs, _ := DecodeBatch(bytes.NewReader(r.body))
	if len(evs) != 1 || evs[0].ID != "high" {
		t.Errorf("min-severity filter wrong; got %+v", evs)
	}
}

func TestForwarderDropsWhenFull(t *testing.T) {
	f := NewForwarder(Target{ID: "t1", URL: "http://127.0.0.1:0", NodeID: "s", QueueSize: 2})
	// Don't Run it, so nothing drains: queue holds 2, the rest are dropped.
	for i := 0; i < 5; i++ {
		f.Enqueue(ev("e", event.SeverityHigh))
	}
	if _, dropped, _ := f.Stats(); dropped != 3 {
		t.Errorf("dropped = %d; want 3", dropped)
	}
}

func TestGroupFanOut(t *testing.T) {
	got1 := make(chan recvd, 2)
	got2 := make(chan recvd, 2)
	s1 := captureServer(t, got1, func(int) int { return 200 })
	s2 := captureServer(t, got2, func(int) int { return 200 })
	defer s1.Close()
	defer s2.Close()
	f1 := NewForwarder(Target{ID: "a", URL: s1.URL, NodeID: "s", MaxBatch: 1, MaxAge: 30 * time.Millisecond})
	f2 := NewForwarder(Target{ID: "b", URL: s2.URL, NodeID: "s", MaxBatch: 1, MaxAge: 30 * time.Millisecond})
	g := NewGroup(f1, f2)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go g.Run(ctx)
	g.Send(ev("e1", event.SeverityHigh))
	waitRecv(t, got1)
	waitRecv(t, got2)
}

func TestSignVerify(t *testing.T) {
	body := []byte("the batch")
	sig := "sha256=" + SignBody([]byte("k"), body)
	if !VerifySignature([]byte("k"), body, sig) {
		t.Error("valid signature should verify")
	}
	if VerifySignature([]byte("k"), []byte("tampered"), sig) {
		t.Error("tampered body must not verify")
	}
	if VerifySignature([]byte("wrong"), body, sig) {
		t.Error("wrong key must not verify")
	}
}

func waitRecv(t *testing.T, got <-chan recvd) recvd {
	t.Helper()
	select {
	case r := <-got:
		return r
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for an ingest request")
		return recvd{}
	}
}
