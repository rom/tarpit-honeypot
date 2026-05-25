package testharness

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// Resilience cases assert the sensor itself does not become the victim: a
// honeypot (and especially a tarpit) must survive abusive clients — giant
// inputs, connection floods, abrupt half-open churn, and slow-drip sessions —
// without crashing, leaking, or letting one bad client starve the rest. These
// are the "fail-safe under load" checks. They run in module mode (each Dial is
// an in-process handler) and against a real network sensor alike.
func init() {
	RegisterGen(CatResilience, func(cfg *Config) []Case {
		var out []Case
		for _, e := range cfg.Endpoints {
			e := e
			if e.Proto != "tcp" {
				continue // these all need a stream socket
			}

			// oversize: a single multi-megabyte line. A handler with an
			// unbounded line/buffer read can be driven to OOM; a fail-safe one
			// bounds the read and stays responsive.
			out = append(out, Case{
				ID: "resilience/oversize/" + e.Label, Category: CatResilience, Endpoint: e.Label,
				Title: "oversize input: " + e.Label,
				Fn: func(ctx context.Context, r *Run) (Status, string, error) {
					ep, _ := r.Target.Endpoint(e.Label)
					payload := make([]byte, 2<<20) // 2 MiB, no newline: an unterminated giant line
					for i := range payload {
						payload[i] = 'A'
					}
					_, _ = probeTimed(ctx, r.Target, ep, payload, 3*time.Second)
					if !r.Target.Alive(ctx) {
						return StatusCrash, "target died on a 2 MiB unterminated input", nil
					}
					if !endpointResponds(ctx, r.Target, ep) {
						return StatusFail, "endpoint unresponsive after oversize input", nil
					}
					return StatusPass, "survived a 2 MiB input; still responsive", nil
				},
			})

			// half-open churn: connect and abandon without (or with partial)
			// data, repeatedly. Catches accept-loop wedges and nil-deref on
			// empty/partial reads.
			out = append(out, Case{
				ID: "resilience/half-open/" + e.Label, Category: CatResilience, Endpoint: e.Label,
				Title: "half-open churn: " + e.Label,
				Fn: func(ctx context.Context, r *Run) (Status, string, error) {
					ep, _ := r.Target.Endpoint(e.Label)
					const n = 40
					for i := 0; i < n; i++ {
						if ctx.Err() != nil {
							return StatusSkip, "interrupted", nil
						}
						conn, err := r.Target.Dial(ctx, ep)
						if err != nil {
							continue // refused connects are not a crash on their own
						}
						if i%2 == 0 {
							_ = conn.SetDeadline(time.Now().Add(200 * time.Millisecond))
							_, _ = conn.Write([]byte{'A'}) // a partial, never-finished request
						}
						_ = conn.Close() // abandon immediately
					}
					if !r.Target.Alive(ctx) {
						return StatusCrash, fmt.Sprintf("target died during %d half-open connects", n), nil
					}
					if !endpointResponds(ctx, r.Target, ep) {
						return StatusFail, "endpoint unresponsive after half-open churn", nil
					}
					return StatusPass, fmt.Sprintf("%d abrupt half-open connects; still responsive", n), nil
				},
			})

			// flood: many *concurrent* connections at once (fd / goroutine /
			// accept-queue pressure), unlike reliability/soak which is serial.
			out = append(out, Case{
				ID: "resilience/flood/" + e.Label, Category: CatResilience, Endpoint: e.Label,
				Title: "connection flood: " + e.Label,
				Fn: func(ctx context.Context, r *Run) (Status, string, error) {
					ep, _ := r.Target.Endpoint(e.Label)
					const n = 64
					var wg sync.WaitGroup
					var mu sync.Mutex
					ok := 0
					for i := 0; i < n; i++ {
						wg.Add(1)
						go func() {
							defer wg.Done()
							c, err := r.Target.Dial(ctx, ep)
							if err != nil {
								return
							}
							_ = c.SetDeadline(time.Now().Add(time.Second))
							_, _ = c.Read(make([]byte, 64)) // touch it, then release
							_ = c.Close()
							mu.Lock()
							ok++
							mu.Unlock()
						}()
					}
					wg.Wait()
					if !r.Target.Alive(ctx) {
						return StatusCrash, fmt.Sprintf("target died under a %d-way connection flood", n), nil
					}
					if !endpointResponds(ctx, r.Target, ep) {
						return StatusFail, "endpoint unresponsive after connection flood", nil
					}
					return StatusPass, fmt.Sprintf("%d/%d concurrent connections accepted; still responsive", ok, n), nil
				},
			})

			// slowloris: hold a connection open dribbling a partial request, and
			// confirm a *separate* client is still served meanwhile. A tarpit is
			// meant to hold the slow client — the finding is only if that starves
			// everyone else or kills the sensor.
			out = append(out, Case{
				ID: "resilience/slowloris/" + e.Label, Category: CatResilience, Endpoint: e.Label,
				Title: "slow-drip starvation: " + e.Label,
				Fn: func(ctx context.Context, r *Run) (Status, string, error) {
					ep, _ := r.Target.Endpoint(e.Label)
					hold, holdCancel := context.WithCancel(ctx)
					defer holdCancel()
					var slow sync.WaitGroup
					slow.Add(1)
					go func() {
						defer slow.Done()
						c, err := r.Target.Dial(ctx, ep)
						if err != nil {
							return
						}
						defer c.Close()
						for i := 0; i < 8; i++ {
							if hold.Err() != nil {
								return
							}
							_ = c.SetWriteDeadline(time.Now().Add(300 * time.Millisecond))
							if _, err := c.Write([]byte("X")); err != nil {
								return
							}
							select {
							case <-hold.Done():
								return
							case <-time.After(150 * time.Millisecond):
							}
						}
					}()
					// while the slow client dribbles, other clients must be served.
					served := 0
					for i := 0; i < 5; i++ {
						if endpointResponds(ctx, r.Target, ep) {
							served++
						}
						time.Sleep(80 * time.Millisecond)
					}
					holdCancel()
					slow.Wait()
					if !r.Target.Alive(ctx) {
						return StatusCrash, "target died during a slow-drip session", nil
					}
					if served == 0 {
						return StatusFail, "a single slow client starved all other connections", nil
					}
					return StatusPass, fmt.Sprintf("%d/5 other clients served while a slow client was held", served), nil
				},
			})
		}
		return out
	})
}
