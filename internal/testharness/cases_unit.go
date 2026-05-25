package testharness

import (
	"context"
	"fmt"
)

func init() {
	// unit: the endpoint is reachable and answers like the service it claims.
	RegisterGen(CatUnit, func(cfg *Config) []Case {
		var out []Case
		for _, e := range cfg.Endpoints {
			e := e
			out = append(out, Case{
				ID: "unit/port-open/" + e.Label, Category: CatUnit, Endpoint: e.Label,
				Title: "port open: " + e.Label,
				Fn: func(ctx context.Context, r *Run) (Status, string, error) {
					ep, ok := r.Target.Endpoint(e.Label)
					if !ok {
						return StatusError, "endpoint not found", nil
					}
					conn, err := r.Target.Dial(ctx, ep)
					if err != nil {
						return StatusFail, "not reachable: " + err.Error(), nil
					}
					_ = conn.Close()
					return StatusPass, "reachable", nil
				},
			})
			out = append(out, Case{
				ID: "unit/banner/" + e.Label, Category: CatUnit, Endpoint: e.Label,
				Title: "banner shape: " + e.Label,
				Fn: func(ctx context.Context, r *Run) (Status, string, error) {
					ep, _ := r.Target.Endpoint(e.Label)
					spec, known := specFor(ep)
					var probe []byte
					if known && !spec.ServerFirst {
						probe = spec.Probe
					}
					resp, err := probe2(ctx, r.Target, ep, probe)
					if err != nil {
						return StatusFail, "no response: " + err.Error(), nil
					}
					if len(resp) == 0 {
						if known && spec.NoReply {
							return StatusPass, "accept-only service (no banner by design); reachable", nil
						}
						return StatusFail, "empty response", nil
					}
					if known && len(spec.Banner) > 0 && !containsAll(resp, spec.Banner) {
						return StatusFail, fmt.Sprintf("response missing %v: %q", spec.Banner, snippet(resp)), nil
					}
					return StatusPass, fmt.Sprintf("%d bytes: %q", len(resp), snippet(resp)), nil
				},
			})
		}
		return out
	})

	// emulate: speak the real protocol and check the response is compatible —
	// catches a broken / incompatible emulation or setup.
	RegisterGen(CatEmulate, func(cfg *Config) []Case {
		var out []Case
		for _, e := range cfg.Endpoints {
			e := e
			if _, known := specs[e.Handler]; !known {
				continue
			}
			out = append(out, Case{
				ID: "emulate/" + e.Label, Category: CatEmulate, Endpoint: e.Label,
				Title: "protocol emulation: " + e.Label,
				Fn: func(ctx context.Context, r *Run) (Status, string, error) {
					ep, _ := r.Target.Endpoint(e.Label)
					spec, _ := specFor(ep)
					resp, err := probe2(ctx, r.Target, ep, spec.Probe)
					if err != nil {
						return StatusFail, "exchange failed: " + err.Error(), nil
					}
					if spec.EmulateOK != nil && !spec.EmulateOK(resp) {
						return StatusFail, fmt.Sprintf("incompatible response: %q", snippet(resp)), nil
					}
					return StatusPass, fmt.Sprintf("compatible (%d bytes)", len(resp)), nil
				},
			})
		}
		return out
	})
}

// probe2 dials, optionally reads a server-first banner, sends the probe, reads
// the reply. For server-first protocols a nil probe still returns the greeting.
func probe2(ctx context.Context, t *Target, e Endpoint, send []byte) ([]byte, error) {
	return probe(ctx, t, e, send)
}

func snippet(b []byte) string {
	const n = 80
	s := b
	if len(s) > n {
		s = s[:n]
	}
	out := make([]rune, 0, len(s))
	for _, c := range string(s) {
		if c == '\n' || c == '\r' || c == '\t' || (c >= 0x20 && c < 0x7f) {
			out = append(out, c)
		} else {
			out = append(out, '.')
		}
	}
	r := string(out)
	if len(b) > n {
		r += "…"
	}
	return r
}
