package handler

import (
	"strings"
	"testing"
)

func TestK8sAPIVersionProbe(t *testing.T) {
	resp, _ := roundTrip(t, newK8sAPI(nil), "GET /version HTTP/1.1\r\nHost: x\r\n\r\n")
	if !strings.Contains(resp, "gitVersion") || !strings.Contains(resp, "v1.28") {
		t.Errorf("version probe missing kube version: %q", resp)
	}
}

func TestK8sAPIBearerTokenCaptured(t *testing.T) {
	_, res := roundTrip(t, newK8sAPI(nil),
		"GET /api/v1/namespaces/default/secrets HTTP/1.1\r\nHost: x\r\n"+
			"Authorization: Bearer eyJhbG.hONEY.tOKEN\r\n\r\n")
	if res.Meta["bearer_token"] != "eyJhbG.hONEY.tOKEN" {
		t.Errorf("bearer token not captured: %v", res.Meta["bearer_token"])
	}
	if !hasAnomaly(res, "k8s-token-auth") {
		t.Errorf("token auth not flagged: %v", anomaliesOf(res))
	}
	if !hasAnomaly(res, "k8s-secret-enum") {
		t.Errorf("secret enumeration not flagged: %v", anomaliesOf(res))
	}
}

func TestK8sAPIPodExecFlagged(t *testing.T) {
	_, res := roundTrip(t, newK8sAPI(nil),
		"POST /api/v1/namespaces/default/pods/x/exec HTTP/1.1\r\nHost: x\r\n\r\n")
	if !hasAnomaly(res, "k8s-pod-exec") {
		t.Errorf("pod exec not flagged: %v", anomaliesOf(res))
	}
}

func TestK8sAPIAnonymousForbidden(t *testing.T) {
	resp, _ := roundTrip(t, newK8sAPI(nil),
		"GET /api/v1/nodes HTTP/1.1\r\nHost: x\r\n\r\n")
	if !strings.HasPrefix(resp, "HTTP/1.1 403") {
		t.Errorf("anonymous protected request should be 403, got %q", resp[:min2(30, len(resp))])
	}
	if !strings.Contains(resp, "system:anonymous") {
		t.Errorf("403 should mention system:anonymous: %q", resp)
	}
}

func TestVaultHealthUnsealed(t *testing.T) {
	resp, _ := roundTrip(t, newVault(nil), "GET /v1/sys/health HTTP/1.1\r\nHost: x\r\n\r\n")
	if !strings.Contains(resp, `"sealed":false`) {
		t.Errorf("health should report unsealed: %q", resp)
	}
}

func TestVaultSecretReadCaptured(t *testing.T) {
	_, res := roundTrip(t, newVault(nil),
		"GET /v1/secret/data/prod/db HTTP/1.1\r\nHost: x\r\nX-Vault-Token: s.honeyTOKEN1234\r\n\r\n")
	if res.Meta["vault_token"] != "s.honeyTOKEN1234" {
		t.Errorf("vault token not captured: %v", res.Meta["vault_token"])
	}
	if !hasAnomaly(res, "vault-token-auth") {
		t.Errorf("token auth not flagged: %v", anomaliesOf(res))
	}
	if !hasAnomaly(res, "vault-secret-read") {
		t.Errorf("secret read not flagged: %v", anomaliesOf(res))
	}
}

func TestVaultSecretReadNoTokenForbidden(t *testing.T) {
	resp, res := roundTrip(t, newVault(nil),
		"GET /v1/secret/data/prod/db HTTP/1.1\r\nHost: x\r\n\r\n")
	if !strings.HasPrefix(resp, "HTTP/1.1 403") {
		t.Errorf("tokenless secret read should be 403, got %q", resp[:min2(30, len(resp))])
	}
	if !hasAnomaly(res, "vault-secret-read") {
		t.Errorf("secret read attempt should still be flagged: %v", anomaliesOf(res))
	}
}

// TestVaultRequestIDFreshPerResponse confirms request_id varies per response
// (as real Vault returns) while the secret password stays deployment-stable.
func TestVaultRequestIDFreshPerResponse(t *testing.T) {
	h := newVault(nil)
	req := "GET /v1/secret/data/prod/db HTTP/1.1\r\nHost: x\r\nX-Vault-Token: s.t\r\n\r\n"
	r1, _ := roundTrip(t, h, req)
	r2, _ := roundTrip(t, h, req)
	id1 := jsonField(r1, "request_id")
	id2 := jsonField(r2, "request_id")
	if id1 == "" || id2 == "" {
		t.Fatalf("missing request_id: %q / %q", id1, id2)
	}
	if id1 == id2 {
		t.Errorf("request_id should be fresh per response, got %q both times", id1)
	}
	// The secret password must be identical across the two responses.
	if jsonField(r1, "password") != jsonField(r2, "password") {
		t.Errorf("secret password should be deployment-stable across requests")
	}
}

// jsonField extracts the string value of a "key":"value" pair from a response
// body (good enough for these flat test payloads).
func jsonField(body, key string) string {
	marker := `"` + key + `":"`
	i := strings.Index(body, marker)
	if i < 0 {
		return ""
	}
	i += len(marker)
	j := strings.IndexByte(body[i:], '"')
	if j < 0 {
		return ""
	}
	return body[i : i+j]
}
