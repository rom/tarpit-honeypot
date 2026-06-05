package handler

import (
	"slices"
	"strings"
	"testing"

	"github.com/rom/tarpit-honeypot/internal/identity"
)

// The API-recon decoys must return believable content and flag the probe.
func TestWebappAPIEndpoints(t *testing.T) {
	id := identity.New("webapp-api-test")
	cases := []struct {
		line        string
		wantBody    string // substring expected in the response
		wantCT      string // Content-Type substring
		wantAnomaly string // anomaly that must be flagged ("" = none required)
	}{
		{"GET /api HTTP/1.1", `"endpoints"`, "application/json", "webapp:api-probe"},
		{"GET /api/v1 HTTP/1.1", `"openapi"`, "application/json", "webapp:api-probe"},
		{"GET /openapi.json HTTP/1.1", `"openapi":"3.0`, "application/json", "webapp:api-spec-probe"},
		{"GET /swagger.json HTTP/1.1", `"openapi":"3.0`, "application/json", "webapp:api-spec-probe"},
		{"GET /v3/api-docs HTTP/1.1", `"paths"`, "application/json", "webapp:api-spec-probe"},
		{"GET /swagger HTTP/1.1", "swagger-ui", "text/html", "webapp:api-spec-probe"},
		{"GET /swagger-ui.html HTTP/1.1", "SwaggerUIBundle", "text/html", "webapp:api-spec-probe"},
		{"GET /graphql HTTP/1.1", "graphiql", "text/html", ""},
		{"GET /graphiql HTTP/1.1", "graphiql", "text/html", ""},
	}
	for _, c := range cases {
		res := Result{Meta: map[string]any{}}
		out := serveWebapp(c.line, nil, "nginx", id, &res)
		if !strings.Contains(out, "200 OK") {
			t.Errorf("%q: not 200: %q", c.line, firstLineOf(out))
		}
		if !strings.Contains(out, c.wantBody) {
			t.Errorf("%q: body missing %q", c.line, c.wantBody)
		}
		if !strings.Contains(out, c.wantCT) {
			t.Errorf("%q: content-type missing %q", c.line, c.wantCT)
		}
		if c.wantAnomaly != "" && !slices.Contains(anomaliesOf(res), c.wantAnomaly) {
			t.Errorf("%q: anomalies=%v; want %s", c.line, anomaliesOf(res), c.wantAnomaly)
		}
	}
}

// A GraphQL introspection POST gets a believable schema and is flagged.
func TestWebappGraphQLIntrospection(t *testing.T) {
	id := identity.New("webapp-gql-test")
	body := []byte(`{"query":"query IntrospectionQuery { __schema { queryType { name } } }"}`)
	res := Result{Meta: map[string]any{}}
	out := serveWebapp("POST /graphql HTTP/1.1", body, "nginx", id, &res)
	if !strings.Contains(out, "__schema") || !strings.Contains(out, "application/json") {
		t.Errorf("introspection response malformed: %q", out)
	}
	if !slices.Contains(anomaliesOf(res), "webapp:graphql-introspection") {
		t.Errorf("introspection not flagged: %v", anomaliesOf(res))
	}
}

// Secret-file and LFI probes must record WHICH file was targeted in probed_file.
func TestWebappRecordsProbedFile(t *testing.T) {
	id := identity.New("webapp-probe-test")
	cases := []struct {
		line string
		want string
	}{
		{"GET /.env HTTP/1.1", "/.env"},
		{"GET /.git/config HTTP/1.1", "/.git/config"},
		{"GET /config.php.bak HTTP/1.1", "/config.php.bak"},
		{"GET /download.php?file=../../../../etc/passwd HTTP/1.1", "passwd"},
	}
	for _, c := range cases {
		res := Result{Meta: map[string]any{}}
		_ = serveWebapp(c.line, nil, "nginx", id, &res)
		pf, _ := res.Meta["probed_file"].(string)
		if !strings.Contains(pf, c.want) {
			t.Errorf("%q: probed_file = %q, want substring %q", c.line, pf, c.want)
		}
		if !slices.Contains(anomaliesOf(res), "webapp:secret-file-probe") {
			t.Errorf("%q: secret-file-probe not flagged: %v", c.line, anomaliesOf(res))
		}
	}
}

func firstLineOf(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
