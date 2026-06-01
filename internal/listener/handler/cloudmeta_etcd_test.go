package handler

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/identity"
)

// roundTrip drives one HTTP request through an HTTP-shaped handler over a pipe
// and returns the raw response plus the handler Result.
func roundTrip(t *testing.T, h Handler, req string) (string, Result) {
	t.Helper()
	client, server := pipePair(t)
	cfg := config.Listener{Handler: h.Name(), ReadTimeout: time.Second}
	resCh := make(chan Result, 1)
	go func() {
		res, _ := h.Handle(context.Background(), server, cfg)
		resCh <- res
	}()
	_, _ = client.Write([]byte(req))
	buf := make([]byte, 4096)
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	n, _ := client.Read(buf)
	client.Close()
	res := <-resCh
	return string(buf[:n]), res
}

func TestCloudMetaAWSCredentialTheftFlagged(t *testing.T) {
	resp, res := roundTrip(t, &cloudMeta{},
		"GET /latest/meta-data/iam/security-credentials/honeypot-instance-role HTTP/1.1\r\nHost: 169.254.169.254\r\n\r\n")
	if !strings.HasPrefix(resp, "HTTP/1.1 200 OK") {
		t.Fatalf("expected 200, got %q", resp[:min(30, len(resp))])
	}
	if !strings.Contains(resp, "AccessKeyId") {
		t.Errorf("expected synthetic IAM creds in body: %q", resp)
	}
	if res.Meta["cloud_provider"] != "aws" {
		t.Errorf("provider = %v, want aws", res.Meta["cloud_provider"])
	}
	if !hasAnomaly(res, "cloud-credential-theft") {
		t.Errorf("credential theft not flagged: %v", anomaliesOf(res))
	}
}

func TestCloudMetaGCPTokenFlagged(t *testing.T) {
	_, res := roundTrip(t, &cloudMeta{},
		"GET /computeMetadata/v1/instance/service-accounts/default/token HTTP/1.1\r\nMetadata-Flavor: Google\r\n\r\n")
	if res.Meta["cloud_provider"] != "gcp" {
		t.Errorf("provider = %v, want gcp", res.Meta["cloud_provider"])
	}
	if res.Meta["metadata_flavor"] != "Google" {
		t.Errorf("metadata_flavor not captured: %v", res.Meta["metadata_flavor"])
	}
	if !hasAnomaly(res, "cloud-credential-theft") {
		t.Errorf("GCP token theft not flagged: %v", anomaliesOf(res))
	}
}

func TestCloudMetaAzureTokenFlagged(t *testing.T) {
	_, res := roundTrip(t, &cloudMeta{},
		"GET /metadata/identity/oauth2/token?resource=https://management.azure.com/ HTTP/1.1\r\nMetadata: true\r\n\r\n")
	if res.Meta["cloud_provider"] != "azure" {
		t.Errorf("provider = %v, want azure", res.Meta["cloud_provider"])
	}
	if !hasAnomaly(res, "cloud-credential-theft") {
		t.Errorf("Azure token theft not flagged: %v", anomaliesOf(res))
	}
}

func TestCloudMetaBenignBrowseNotFlagged(t *testing.T) {
	_, res := roundTrip(t, &cloudMeta{},
		"GET /latest/meta-data/instance-id HTTP/1.1\r\nHost: 169.254.169.254\r\n\r\n")
	if hasAnomaly(res, "cloud-credential-theft") {
		t.Errorf("benign metadata browse should not flag credential theft")
	}
}

func TestEtcdVersionHealth(t *testing.T) {
	resp, _ := roundTrip(t, &etcd{}, "GET /version HTTP/1.1\r\nHost: x\r\n\r\n")
	if !strings.Contains(resp, "etcdserver") {
		t.Errorf("version probe missing etcdserver field: %q", resp)
	}
}

func TestEtcdSecretReadFlagged(t *testing.T) {
	_, res := roundTrip(t, &etcd{},
		"GET /v2/keys/registry/secrets/default/default-token HTTP/1.1\r\nHost: x\r\n\r\n")
	if !hasAnomaly(res, "etcd-secret-read") {
		t.Errorf("secret read not flagged: %v", anomaliesOf(res))
	}
}

func TestEtcdWriteFlagged(t *testing.T) {
	_, res := roundTrip(t, &etcd{},
		"PUT /v2/keys/foo HTTP/1.1\r\nHost: x\r\nContent-Length: 7\r\n\r\nvalue=1")
	if !hasAnomaly(res, "etcd-write") {
		t.Errorf("write not flagged: %v", anomaliesOf(res))
	}
}

func TestEtcdV3RangeRead(t *testing.T) {
	_, res := roundTrip(t, &etcd{},
		"POST /v3/kv/range HTTP/1.1\r\nHost: x\r\nContent-Length: 2\r\n\r\n{}")
	if len(anomaliesOf(res)) == 0 {
		t.Errorf("v3 range read should flag a range/secret read")
	}
}

// TestCloudCredsPerDeploymentUniqueAndClean asserts the served fake credentials
// are (1) stable for one deployment, (2) unique across deployments, and (3)
// never leak a "honey" tell to the attacker.
func TestCloudCredsPerDeploymentUniqueAndClean(t *testing.T) {
	const req = "GET /latest/meta-data/iam/security-credentials/role HTTP/1.1\r\nHost: 169.254.169.254\r\n\r\n"
	a1, _ := roundTrip(t, &cloudMeta{id: identity.New("dep-A")}, req)
	a2, _ := roundTrip(t, &cloudMeta{id: identity.New("dep-A")}, req)
	b1, _ := roundTrip(t, &cloudMeta{id: identity.New("dep-B")}, req)

	if a1 != a2 {
		t.Errorf("creds not stable for one deployment:\n%s\nvs\n%s", a1, a2)
	}
	if a1 == b1 {
		t.Errorf("creds not unique across deployments (both produced identical bodies)")
	}
	for _, body := range []string{a1, b1} {
		low := strings.ToLower(body)
		if strings.Contains(low, "honey") {
			t.Errorf("served body leaks a honeypot tell: %s", body)
		}
		// Sanity: the AWS access-key id must still have the real ASIA prefix.
		if !strings.Contains(body, `"AccessKeyId":"ASIA`) {
			t.Errorf("AWS key id lost its realistic ASIA prefix: %s", body)
		}
	}
}

func TestVaultEtcdK8sNoHoneyTell(t *testing.T) {
	id := identity.New("dep-X")
	cases := []struct {
		h   Handler
		req string
	}{
		{&vault{id: id}, "GET /v1/secret/data/prod/db HTTP/1.1\r\nHost: x\r\nX-Vault-Token: s.abc\r\n\r\n"},
		{&vault{id: id}, "GET /v1/sys/health HTTP/1.1\r\nHost: x\r\n\r\n"},
		{&etcd{id: id}, "GET /v2/keys/registry/secrets/default/default-token HTTP/1.1\r\nHost: x\r\n\r\n"},
		{&k8sAPI{id: id}, "GET /api/v1/namespaces/default/secrets HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer t\r\n\r\n"},
	}
	for _, c := range cases {
		body, _ := roundTrip(t, c.h, c.req)
		if strings.Contains(strings.ToLower(body), "honey") {
			t.Errorf("%s leaks a honeypot tell: %s", c.h.Name(), body)
		}
	}
}
