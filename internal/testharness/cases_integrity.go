package testharness

import (
	"context"
	crand "crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

// Integrity cases verify the sensor's *evidence* is trustworthy: a marker the
// harness sends must be faithfully recorded (capture fidelity), and a burst of
// marked connections must all be recorded (no dropped events under load). These
// need the sensor's read API (verify.url); without it they skip cleanly. They
// answer the "did the program under test actually capture what happened, and
// does it lose data under pressure" question that a fail-safe security tool
// must be able to assert.
func init() {
	RegisterGen(CatIntegrity, func(cfg *Config) []Case {
		var out []Case
		for _, e := range cfg.Endpoints {
			e := e
			vec, ok := integrityVectors[e.Handler]
			if !ok {
				continue // only handlers with a known text capture field
			}
			out = append(out, Case{
				ID: "integrity/capture/" + e.Label, Category: CatIntegrity, Endpoint: e.Label,
				Title: "capture fidelity: " + e.Label,
				Fn: func(ctx context.Context, r *Run) (Status, string, error) {
					if r.API == nil {
						return StatusSkip, "set verify.url to check capture fidelity", nil
					}
					ep, _ := r.Target.Endpoint(e.Label)
					marker := freshMarker()
					_, _ = probe(ctx, r.Target, ep, vec(marker))
					if !r.Target.Alive(ctx) {
						return StatusCrash, "target died while capturing a marker", nil
					}
					time.Sleep(700 * time.Millisecond) // let the event persist
					found, checked := r.API.Detected(ctx, MatchMetaContains(marker))
					if !checked {
						return StatusSkip, "verify API unreachable", nil
					}
					if !found {
						return StatusFail, "marker sent but not recorded by the sensor — capture gap", nil
					}
					return StatusPass, "marker recorded faithfully", nil
				},
			})
			out = append(out, Case{
				ID: "integrity/no-drop-under-load/" + e.Label, Category: CatIntegrity, Endpoint: e.Label,
				Title: "no dropped events under load: " + e.Label,
				Fn: func(ctx context.Context, r *Run) (Status, string, error) {
					if r.API == nil {
						return StatusSkip, "set verify.url to check for dropped events", nil
					}
					ep, _ := r.Target.Endpoint(e.Label)
					const k = 20
					markers := make([]string, k)
					var wg sync.WaitGroup
					for i := range markers {
						markers[i] = freshMarker()
						m := markers[i]
						wg.Add(1)
						go func() {
							defer wg.Done()
							_, _ = probe(ctx, r.Target, ep, vec(m))
						}()
					}
					wg.Wait()
					if !r.Target.Alive(ctx) {
						return StatusCrash, fmt.Sprintf("target died under a %d-connection capture burst", k), nil
					}
					time.Sleep(time.Second) // let the burst persist
					evs, err := r.API.Events(ctx, "10m", 5000)
					if err != nil {
						return StatusSkip, "verify API unreachable", nil
					}
					recorded := 0
					for _, m := range markers {
						match := MatchMetaContains(m)
						for _, ev := range evs {
							if match(ev) {
								recorded++
								break
							}
						}
					}
					if recorded < k {
						return StatusFail, fmt.Sprintf("only %d/%d marked connections recorded — events dropped under load", recorded, k), nil
					}
					return StatusPass, fmt.Sprintf("all %d marked connections recorded", k), nil
				},
			})
		}
		return out
	})
}

// integrityVectors embeds the marker in a field the handler captures into a
// *recorded* event (a login attempt for the credential protocols, the request
// line/UA for HTTP), so the capture check exercises the real capture+persist
// path rather than a benign connection the sensor may not store.
var integrityVectors = map[string]func(marker string) []byte{
	"http":  func(m string) []byte { return []byte("GET /?q=" + m + " HTTP/1.0\r\nUser-Agent: " + m + "\r\n\r\n") },
	"https": func(m string) []byte { return []byte("GET /?q=" + m + " HTTP/1.0\r\nUser-Agent: " + m + "\r\n\r\n") },
	"ftp":   func(m string) []byte { return []byte("USER " + m + "\r\nPASS " + m + "\r\nQUIT\r\n") },
	"smtp_recv": func(m string) []byte {
		return []byte("EHLO " + m + "\r\nMAIL FROM:<" + m + "@x>\r\nRCPT TO:<" + m + "@y>\r\nQUIT\r\n")
	},
	"telnet": func(m string) []byte { return []byte(m + "\r\n" + m + "\r\n") },
	"imap":   func(m string) []byte { return []byte("a1 LOGIN " + m + " " + m + "\r\na2 LOGOUT\r\n") },
	"pop3":   func(m string) []byte { return []byte("USER " + m + "\r\nPASS " + m + "\r\nQUIT\r\n") },
}

// freshMarker returns a unique, protocol-safe correlation token. It is
// deliberately NOT derived from the run seed: it must differ every run so a
// stale event from a prior run (within the API's lookback) can't cause a false
// "captured".
func freshMarker() string {
	b := make([]byte, 8)
	_, _ = crand.Read(b)
	return "TPHI" + hex.EncodeToString(b)
}
