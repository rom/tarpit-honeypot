package testharness

import (
	"context"
	"fmt"
	"net"
	"sync/atomic"
	"time"
)

// Containment cases assert the "do no harm" invariant: a honeypot must never be
// turned into an attack platform. Two threats are covered:
//
//   - egress / relay / SSRF / reflection: the sensor is fed an attacker-chosen
//     target address and must NOT connect out to it. We stand up a canary
//     listener and confirm it receives zero connections.
//   - host-file disclosure via path traversal: file-surface protocols
//     (http / ftp) are asked for ../../etc/passwd and the reply must not contain
//     real host-file contents.
//
// These are best-effort by construction (they prove the invariant for the
// payloads tried), but they catch the high-impact regressions — e.g. someone
// later adds an outbound fetch, open relay, or a real filesystem read.
func init() {
	RegisterGen(CatContainment, func(cfg *Config) []Case {
		var out []Case

		// no-egress: one whole-target case. Embed a canary address in the
		// payloads most likely to induce an outbound connection (HTTP absolute
		// URI + CONNECT, and a raw address line) and assert the canary stays
		// silent.
		hasTCP := false
		for _, e := range cfg.Endpoints {
			if e.Proto == "tcp" {
				hasTCP = true
				break
			}
		}
		if hasTCP {
			out = append(out, Case{
				ID: "containment/no-egress", Category: CatContainment,
				Title: "no outbound connection to an attacker-chosen target",
				Fn: func(ctx context.Context, r *Run) (Status, string, error) {
					ln, err := net.Listen("tcp", "127.0.0.1:0")
					if err != nil {
						return StatusError, "", fmt.Errorf("canary listen: %w", err)
					}
					defer ln.Close()
					var hits int32
					go func() {
						for {
							c, err := ln.Accept()
							if err != nil {
								return
							}
							atomic.AddInt32(&hits, 1)
							_ = c.Close()
						}
					}()
					canary := ln.Addr().String()
					payloads := [][]byte{
						[]byte("GET http://" + canary + "/ HTTP/1.1\r\nHost: " + canary + "\r\n\r\n"),
						[]byte("CONNECT " + canary + " HTTP/1.1\r\nHost: " + canary + "\r\n\r\n"),
						[]byte("http://" + canary + "/\r\n"),
						[]byte(canary + "\r\n"),
					}
					for _, e := range r.Cfg.Endpoints {
						if e.Proto != "tcp" {
							continue
						}
						ep, _ := r.Target.Endpoint(e.Label)
						for _, p := range payloads {
							if ctx.Err() != nil {
								return StatusSkip, "interrupted", nil
							}
							_, _ = probeTimed(ctx, r.Target, ep, p, 700*time.Millisecond)
						}
					}
					time.Sleep(300 * time.Millisecond) // let any late dial land
					if n := atomic.LoadInt32(&hits); n > 0 {
						return StatusFail, fmt.Sprintf("sensor made %d outbound connection(s) to an attacker-chosen address (SSRF / relay / reflector risk)", n), nil
					}
					return StatusPass, "no outbound connection to the canary across all endpoints", nil
				},
			})
		}

		// path traversal on file-surface protocols.
		for _, e := range cfg.Endpoints {
			e := e
			if e.Proto != "tcp" {
				continue
			}
			var payloads [][]byte
			switch e.Handler {
			case "http", "https":
				payloads = [][]byte{
					[]byte("GET /../../../../../../etc/passwd HTTP/1.0\r\n\r\n"),
					[]byte("GET /..%2f..%2f..%2f..%2fetc/passwd HTTP/1.0\r\n\r\n"),
				}
			case "ftp":
				payloads = [][]byte{
					[]byte("USER anonymous\r\nPASS x\r\nRETR ../../../../../../etc/passwd\r\nSTAT ../../../../etc/passwd\r\nQUIT\r\n"),
				}
			default:
				continue
			}
			out = append(out, Case{
				ID: "containment/path-traversal/" + e.Label, Category: CatContainment, Endpoint: e.Label,
				Title: "no host-file disclosure via traversal: " + e.Label,
				Fn: func(ctx context.Context, r *Run) (Status, string, error) {
					ep, _ := r.Target.Endpoint(e.Label)
					for _, p := range payloads {
						if ctx.Err() != nil {
							return StatusSkip, "interrupted", nil
						}
						resp, _ := probeTimed(ctx, r.Target, ep, p, 2*time.Second)
						if looksLikeHostFile(resp) {
							return StatusFail, fmt.Sprintf("traversal returned real host-file content: %q", snippet(resp)), nil
						}
					}
					if !r.Target.Alive(ctx) {
						return StatusCrash, "target died on a path-traversal request", nil
					}
					return StatusPass, "traversal did not disclose host files", nil
				},
			})
		}
		return out
	})
}

// looksLikeHostFile reports whether a response contains tell-tale real host-file
// content (a leaked /etc/passwd or Windows boot config).
func looksLikeHostFile(resp []byte) bool {
	return containsAll(resp, []string{"root:x:0:0:"}) ||
		containsAll(resp, []string{"daemon:x:1:1:"}) ||
		containsAll(resp, []string{"[boot loader]"})
}
