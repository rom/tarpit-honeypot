package handler

import (
	"bufio"
	"context"
	"crypto/rand"
	"fmt"
	"net"
	"strings"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/identity"
)

// randomUUID returns a fresh random 8-4-4-4-12 hex UUID, formatted like the
// per-response request_id a real Vault returns.
func randomUUID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return guidFrom(b[:])
}

// vault emulates HashiCorp Vault's HTTP API (TCP 8200). Vault is the crown
// jewels — it holds every secret, DB credential and cloud key an org has.
// Attackers probe /v1/sys/health and /v1/sys/seal-status to find it, then try
// to read secrets with a stolen or guessed token. We answer the health/seal
// probes like a real (unsealed) Vault, capture the X-Vault-Token, and flag
// secret reads and the dangerous sys paths (unseal, policies, mounts).
// Detection only.
type vault struct {
	// clusterName + secretPW are deployment-constant, derived once at
	// construction so they aren't recomputed (sha256 + RNG) per request.
	clusterName string
	secretPW    string
}

func (v *vault) Name() string { return "vault" }

// newVault derives the per-deployment cluster name + secret password once.
func newVault(id *identity.Identity) *vault {
	return &vault{
		clusterName: "vault-cluster-" + encodeAlpha(idBytes(id, "vault-cluster", 6), "0123456789abcdef"),
		secretPW:    encodeAlpha(idBytes(id, "vault-secret-pw", 16), honeyAlnum),
	}
}

func (v *vault) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	withTimeout(conn, cfg.ReadTimeout)
	res := Result{Meta: map[string]any{}}
	br := bufio.NewReader(conn)
	capN := cfg.ReadBytes
	if capN <= 0 {
		capN = 8192
	}
	head, _ := readHTTPHead(br, capN)
	res.Payload = head

	method, path := "", ""
	for i, line := range strings.Split(string(head), "\r\n") {
		if i == 0 {
			res.Meta["request_line"] = line
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				method, path = strings.ToUpper(parts[0]), parts[1]
			}
			continue
		}
		lower := strings.ToLower(line)
		switch {
		case strings.HasPrefix(lower, "x-vault-token:"):
			tok := strings.TrimSpace(line[14:])
			res.Meta["vault_token"] = tok
			flagAnomaly(&res, "vault-token-auth")
		case strings.HasPrefix(lower, "authorization:"):
			res.Meta["authorization"] = strings.TrimSpace(line[14:])
		case strings.HasPrefix(lower, "user-agent:"):
			res.Meta["user_agent"] = strings.TrimSpace(line[11:])
		}
	}
	res.Meta["method"] = method
	res.Meta["path"] = path

	low := strings.ToLower(path)
	body, status := v.route(method, low, &res)
	resp := "HTTP/1.1 " + status + "\r\n" +
		"Content-Type: application/json\r\n" +
		"Cache-Control: no-store\r\n" +
		"Content-Length: " + intToStr(len(body)) + "\r\n" +
		"Connection: close\r\n\r\n" + body
	if _, err := conn.Write([]byte(resp)); err != nil {
		res.Meta["write_err"] = err.Error()
	}
	res.BannerSent = "vault " + status
	return res, nil
}

func (v *vault) route(method, low string, res *Result) (body, status string) {
	status = "200 OK"
	_, hasToken := res.Meta["vault_token"]
	switch {
	case strings.HasPrefix(low, "/v1/sys/health"):
		body = fmt.Sprintf(`{"initialized":true,"sealed":false,"standby":false,"version":"1.15.2","cluster_name":%q}`, v.clusterName)
	case strings.HasPrefix(low, "/v1/sys/seal-status"):
		body = `{"type":"shamir","initialized":true,"sealed":false,"t":3,"n":5,"version":"1.15.2"}`
	case strings.HasPrefix(low, "/v1/sys/unseal") || strings.HasPrefix(low, "/v1/sys/seal"):
		flagAnomaly(res, "vault-seal-control")
		status = "403 Forbidden"
		body = vaultErr("permission denied")
	case strings.HasPrefix(low, "/v1/sys/policies") || strings.HasPrefix(low, "/v1/sys/policy"):
		flagAnomaly(res, "vault-policy-access")
		if !hasToken {
			status = "403 Forbidden"
			body = vaultErr("permission denied")
		} else {
			body = `{"policies":["default","root"]}`
		}
	case strings.HasPrefix(low, "/v1/sys/mounts"):
		flagAnomaly(res, "vault-mount-enum")
		body = `{"secret/":{"type":"kv","description":"key/value secret storage"},"database/":{"type":"database"},"aws/":{"type":"aws"}}`
	case strings.HasPrefix(low, "/v1/secret/") || strings.HasPrefix(low, "/v1/kv/") ||
		strings.HasPrefix(low, "/v1/database/creds/") || strings.HasPrefix(low, "/v1/aws/creds/"):
		flagAnomaly(res, "vault-secret-read")
		if !hasToken {
			status = "403 Forbidden"
			body = vaultErr("permission denied")
		} else {
			// A believable KV v2 secret payload. The password is the
			// deployment-constant bait; request_id is fresh per response, as a
			// real Vault returns. No "honey" tell — a scanner that reads it
			// can't distinguish it from a real Vault secret; detection fires on
			// the path hit.
			body = fmt.Sprintf(`{"request_id":%q,"lease_id":"","renewable":false,"lease_duration":2764800,"data":{"data":{"password":%q,"username":"svc-prod"},"metadata":{"created_time":"2099-01-01T00:00:00Z","version":1}}}`,
				randomUUID(), v.secretPW)
		}
	default:
		status = "404 Not Found"
		body = vaultErr("")
	}
	return
}

func vaultErr(msg string) string {
	if msg == "" {
		return `{"errors":[]}`
	}
	return `{"errors":["` + msg + `"]}`
}
