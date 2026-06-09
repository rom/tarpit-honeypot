package handler

import (
	"strings"
	"testing"

	"github.com/rom/tarpit-honeypot/internal/archetype"
)

func TestServeProductAPI(t *testing.T) {
	cases := []struct {
		arch, path, wantSub string
	}{
		{"aveva-pi", "/piwebapi/system", `"Self"`},
		{"aveva-pi", "/piwebapi/dataservers", `"ServerVersion"`},
		{"ge-proficy-historian", "/ProficyHistorian", "Proficy Historian"},
		{"canary-historian", "/CanaryData", `"statusCode"`},
		{"dataparc", "/PARCview", "PARCview"},
		{"ignition-gateway", "/system/gwinfo", `"gatewayName"`},
		{"influxdb", "/health", `"status":"pass"`},
		{"keycloak-server", "/realms/master/.well-known/openid-configuration", `"issuer"`},
	}
	for _, c := range cases {
		p := archetype.Lookup(c.arch)
		if p == nil {
			t.Fatalf("archetype %q not found", c.arch)
		}
		body, ct, ok := serveProductAPI(p, "GET", c.path)
		if !ok {
			t.Errorf("%s %s: expected a product-API response", c.arch, c.path)
			continue
		}
		if !strings.Contains(body, c.wantSub) {
			t.Errorf("%s %s: body %q missing %q", c.arch, c.path, body, c.wantSub)
		}
		if ct == "" {
			t.Errorf("%s %s: empty content-type", c.arch, c.path)
		}
	}
	// A non-product archetype must NOT answer these paths.
	if _, _, ok := serveProductAPI(archetype.Lookup("debian-12"), "GET", "/piwebapi/system"); ok {
		t.Error("debian-12 should not serve /piwebapi")
	}
}
