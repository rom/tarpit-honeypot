package testharness

import (
	"context"
	"fmt"
	"time"
)

func init() {
	// misimpl: deliberately mis-frame a protocol and confirm the honeypot
	// CATCHES it (records the expected anomaly). Detection is verified via the
	// target's API; without it the case reports skip (and still checks the
	// target didn't crash).
	RegisterGen(CatMisimpl, func(cfg *Config) []Case {
		var out []Case
		for _, e := range cfg.Endpoints {
			e := e
			spec, known := specs[e.Handler]
			if !known || len(spec.Misimpl) == 0 {
				continue
			}
			for _, mc := range spec.Misimpl {
				mc := mc
				out = append(out, Case{
					ID: "misimpl/" + e.Label + "/" + mc.Name, Category: CatMisimpl, Endpoint: e.Label,
					Title: "mis-implementation caught: " + e.Label + " " + mc.Name,
					Fn: func(ctx context.Context, r *Run) (Status, string, error) {
						ep, _ := r.Target.Endpoint(e.Label)
						_, _ = probe(ctx, r.Target, ep, mc.Bytes)
						if !r.Target.Alive(ctx) {
							return StatusCrash, "target died on mis-framed " + mc.Name, nil
						}
						if r.API == nil {
							return StatusSkip, "sent " + mc.Name + "; set verify.url to confirm detection", nil
						}
						time.Sleep(400 * time.Millisecond) // let the event persist
						m := MatchAnomaly(mc.Anomaly)
						if mc.Anomaly == "" {
							m = MatchRulePrefix("listener:")
						}
						detected, checked := r.API.Detected(ctx, m)
						if !checked {
							return StatusSkip, "verify API unreachable", nil
						}
						if detected {
							return StatusPass, "honeypot recorded " + mc.Anomaly, nil
						}
						return StatusFail, "honeypot did NOT flag " + mc.Anomaly + " for " + mc.Name, nil
					},
				})
			}
		}
		return out
	})

	// reliability: rapid open/close connection churn to confirm the endpoint
	// stays responsive (no fd leak / accept-loop wedge under repeated
	// short-lived sessions). Liveness is re-checked periodically and at the end.
	RegisterGen(CatReliability, func(cfg *Config) []Case {
		var out []Case
		for _, e := range cfg.Endpoints {
			e := e
			out = append(out, Case{
				ID: "reliability/soak/" + e.Label, Category: CatReliability, Endpoint: e.Label,
				Title: "soak: " + e.Label,
				Fn: func(ctx context.Context, r *Run) (Status, string, error) {
					ep, _ := r.Target.Endpoint(e.Label)
					const rounds = 50
					ok := 0
					for i := 0; i < rounds; i++ {
						if ctx.Err() != nil {
							break
						}
						if endpointResponds(ctx, r.Target, ep) {
							ok++
						}
						if i%10 == 9 && !r.Target.Alive(ctx) {
							return StatusCrash, fmt.Sprintf("target died during soak (after %d/%d connections)", i+1, rounds), nil
						}
					}
					if !r.Target.Alive(ctx) {
						return StatusCrash, "target unresponsive after soak", nil
					}
					if ok < rounds*9/10 {
						return StatusFail, itoa(ok) + "/" + itoa(rounds) + " soak connections succeeded", nil
					}
					return StatusPass, itoa(ok) + "/" + itoa(rounds) + " rapid connections healthy", nil
				},
			})
		}
		return out
	})
}
