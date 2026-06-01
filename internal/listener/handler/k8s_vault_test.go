package handler

import (
	"strings"
	"testing"
)

func TestK8sAPIVersionProbe(t *testing.T) {
	resp, _ := roundTrip(t, &k8sAPI{}, "GET /version HTTP/1.1\r\nHost: x\r\n\r\n")
	if !strings.Contains(resp, "gitVersion") || !strings.Contains(resp, "v1.28") {
		t.Errorf("version probe missing kube version: %q", resp)
	}
}

func TestK8sAPIBearerTokenCaptured(t *testing.T) {
	_, res := roundTrip(t, &k8sAPI{},
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
	_, res := roundTrip(t, &k8sAPI{},
		"POST /api/v1/namespaces/default/pods/x/exec HTTP/1.1\r\nHost: x\r\n\r\n")
	if !hasAnomaly(res, "k8s-pod-exec") {
		t.Errorf("pod exec not flagged: %v", anomaliesOf(res))
	}
}

func TestK8sAPIAnonymousForbidden(t *testing.T) {
	resp, _ := roundTrip(t, &k8sAPI{},
		"GET /api/v1/nodes HTTP/1.1\r\nHost: x\r\n\r\n")
	if !strings.HasPrefix(resp, "HTTP/1.1 403") {
		t.Errorf("anonymous protected request should be 403, got %q", resp[:min2(30, len(resp))])
	}
	if !strings.Contains(resp, "system:anonymous") {
		t.Errorf("403 should mention system:anonymous: %q", resp)
	}
}

func TestVaultHealthUnsealed(t *testing.T) {
	resp, _ := roundTrip(t, &vault{}, "GET /v1/sys/health HTTP/1.1\r\nHost: x\r\n\r\n")
	if !strings.Contains(resp, `"sealed":false`) {
		t.Errorf("health should report unsealed: %q", resp)
	}
}

func TestVaultSecretReadCaptured(t *testing.T) {
	_, res := roundTrip(t, &vault{},
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
	resp, res := roundTrip(t, &vault{},
		"GET /v1/secret/data/prod/db HTTP/1.1\r\nHost: x\r\n\r\n")
	if !strings.HasPrefix(resp, "HTTP/1.1 403") {
		t.Errorf("tokenless secret read should be 403, got %q", resp[:min2(30, len(resp))])
	}
	if !hasAnomaly(res, "vault-secret-read") {
		t.Errorf("secret read attempt should still be flagged: %v", anomaliesOf(res))
	}
}
