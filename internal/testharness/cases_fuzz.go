package testharness

import (
	"context"
	"fmt"
	"hash/fnv"
	"math/rand"
)

func init() {
	// fuzz-dumb: protocol-unaware random input. The aim is to crash or hang
	// the target; the signal is a liveness re-check after each input.
	RegisterGen(CatFuzzDumb, func(cfg *Config) []Case {
		var out []Case
		for _, e := range cfg.Endpoints {
			e := e
			out = append(out, Case{
				ID: "fuzz-dumb/" + e.Label, Category: CatFuzzDumb, Endpoint: e.Label,
				Title: "dumb fuzz: " + e.Label,
				Fn: func(ctx context.Context, r *Run) (Status, string, error) {
					ep, _ := r.Target.Endpoint(e.Label)
					rng := caseRand(r.Cfg.Seed, "fuzz-dumb/"+e.Label)
					n := r.Cfg.FuzzIterations
					for i := 0; i < n; i++ {
						if ctx.Err() != nil {
							return StatusSkip, "interrupted", nil
						}
						_, _ = probe(ctx, r.Target, ep, randBytes(rng)) // per-input errors are expected
						if !r.Target.Alive(ctx) {
							return StatusCrash, fmt.Sprintf("target died after input %d/%d (seed %d — replay with --seed)", i+1, n, r.Cfg.Seed), nil
						}
					}
					if !endpointResponds(ctx, r.Target, ep) {
						return StatusFail, fmt.Sprintf("endpoint unresponsive after %d inputs (seed %d)", n, r.Cfg.Seed), nil
					}
					return StatusPass, fmt.Sprintf("%d random inputs; endpoint healthy (seed %d)", n, r.Cfg.Seed), nil
				},
			})
		}
		return out
	})

	// fuzz-smart: protocol-aware malformed inputs (oversized fields, bad
	// lengths, illegal framing) that a dumb fuzzer rarely reaches.
	RegisterGen(CatFuzzSmart, func(cfg *Config) []Case {
		var out []Case
		for _, e := range cfg.Endpoints {
			e := e
			spec, known := specs[e.Handler]
			if !known || len(spec.Smart) == 0 {
				continue
			}
			out = append(out, Case{
				ID: "fuzz-smart/" + e.Label, Category: CatFuzzSmart, Endpoint: e.Label,
				Title: "smart fuzz: " + e.Label,
				Fn: func(ctx context.Context, r *Run) (Status, string, error) {
					ep, _ := r.Target.Endpoint(e.Label)
					sp, _ := specFor(ep)
					rng := caseRand(r.Cfg.Seed, "fuzz-smart/"+e.Label)
					for i := 0; i < r.Cfg.FuzzIterations; i++ {
						if ctx.Err() != nil {
							return StatusSkip, "interrupted", nil
						}
						base := sp.Smart[i%len(sp.Smart)]
						_, _ = probe(ctx, r.Target, ep, mutate(rng, base.Bytes))
						if !r.Target.Alive(ctx) {
							return StatusCrash, fmt.Sprintf("target died on %q-class input (seed %d)", base.Name, r.Cfg.Seed), nil
						}
					}
					if !endpointResponds(ctx, r.Target, ep) {
						return StatusFail, "endpoint unresponsive after smart fuzz", nil
					}
					return StatusPass, fmt.Sprintf("%d protocol-aware inputs across %d shapes; healthy", r.Cfg.FuzzIterations, len(sp.Smart)), nil
				},
			})
		}
		return out
	})
}

func caseRand(seed int64, id string) *rand.Rand {
	h := fnv.New64a()
	_, _ = h.Write([]byte(id))
	return rand.New(rand.NewSource(seed ^ int64(h.Sum64()))) //nolint:gosec // reproducibility, not crypto
}

func randBytes(rng *rand.Rand) []byte {
	n := rng.Intn(2048)
	if rng.Intn(8) == 0 {
		n = rng.Intn(16384) // occasional oversized input
	}
	b := make([]byte, n)
	_, _ = rng.Read(b)
	return b
}

// mutate flips a few bytes / truncates / extends a base input so a smart-fuzz
// case explores around each malformed shape (deterministic given the rng).
func mutate(rng *rand.Rand, base []byte) []byte {
	b := append([]byte(nil), base...)
	switch rng.Intn(4) {
	case 0: // bit flips
		for i := 0; i < 1+rng.Intn(8) && len(b) > 0; i++ {
			b[rng.Intn(len(b))] ^= byte(1 << uint(rng.Intn(8)))
		}
	case 1: // truncate
		if len(b) > 1 {
			b = b[:rng.Intn(len(b))]
		}
	case 2: // extend with random bytes
		ext := make([]byte, rng.Intn(512))
		_, _ = rng.Read(ext)
		b = append(b, ext...)
	default: // as-is
	}
	return b
}

func endpointResponds(ctx context.Context, t *Target, e Endpoint) bool {
	conn, err := t.Dial(ctx, e)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}
