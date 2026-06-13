package handler

import (
	"bufio"
	"context"
	"net"
	"strings"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/safe"
)

// dockerRegistry emulates a Docker Registry v2 (Distribution) HTTP API
// (TCP 5000). An exposed, unauthenticated registry leaks every image — and
// image configs/layers routinely contain baked-in secrets. The /v2/ endpoint
// plus the Docker-Distribution-Api-Version header is the fingerprint scanners
// key on; /v2/_catalog enumerates all repositories. We answer the API probes
// believably, flag the enumeration and manifest/blob pulls, and serve nothing
// real.
type dockerRegistry struct{}

func (d *dockerRegistry) Name() string { return "docker_registry" }

func (d *dockerRegistry) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	withTimeout(conn, cfg.ReadTimeout)
	res := Result{Meta: map[string]any{}}
	br := bufio.NewReader(conn)
	capN := cfg.ReadBytes
	if capN <= 0 {
		capN = 8192
	}
	head, _ := readHTTPHead(br, capN)
	res.Payload = head

	method, path, _, authz, ua := svcHTTPReqLine(head)
	res.Meta["method"] = method
	res.Meta["path"] = safe.SanitizeForLog(path)
	if authz != "" {
		res.Meta["authorization"] = safe.SanitizeForLog(authz)
	}
	if ua != "" {
		res.Meta["user_agent"] = safe.SanitizeForLog(ua)
	}
	flagAnomaly(&res, "docker-registry-access")

	// The API-version header rides on every response — that's the fingerprint.
	const apiVer = "Docker-Distribution-Api-Version: registry/2.0\r\n"
	low := strings.ToLower(path)
	ctype, status, body := "application/json", "200 OK", "{}"
	switch {
	case low == "/v2" || low == "/v2/":
		setIfEmpty(res.Meta, "intent", "Docker Registry v2 probe — fingerprinting an exposed registry")
	case low == "/v2/_catalog":
		flagAnomaly(&res, "docker-registry-catalog")
		res.Meta["intent"] = "Docker Registry _catalog — enumerating all repositories (info disclosure)"
		body = `{"repositories":["library/nginx","app/backend-api","internal/db-migrator","ci/build-runner"]}`
	case strings.HasSuffix(low, "/tags/list"):
		flagAnomaly(&res, "docker-registry-enum")
		setIfEmpty(res.Meta, "intent", "Docker Registry tags/list — enumerating image tags")
		body = `{"name":"` + dockerRegistryRepo(path) + `","tags":["latest","v1.0","v1.1","stable"]}`
	case strings.Contains(low, "/manifests/"):
		flagAnomaly(&res, "docker-registry-pull")
		res.Meta["intent"] = "Docker Registry manifest pull — fetching image config (potential secret exfiltration)"
		ctype = "application/vnd.docker.distribution.manifest.v2+json"
		body = `{"schemaVersion":2,"mediaType":"application/vnd.docker.distribution.manifest.v2+json","config":{"mediaType":"application/vnd.docker.container.image.v1+json","size":7023,"digest":"sha256:b5b2b2c507a0944348e0303114d8d93aaaa081732b86451d9bce1f432a537bc7"},"layers":[]}`
	case strings.Contains(low, "/blobs/"):
		flagAnomaly(&res, "docker-registry-pull")
		res.Meta["intent"] = "Docker Registry blob pull — fetching image layer data (potential exfiltration)"
	default:
		status, body = "404 Not Found", `{"errors":[{"code":"NAME_UNKNOWN","message":"repository name not known to registry"}]}`
	}

	if _, err := conn.Write([]byte(svcHTTPResp(status, apiVer, ctype, body))); err != nil {
		res.Meta["write_err"] = err.Error()
	}
	res.BannerSent = "docker_registry " + status
	return res, nil
}

// dockerRegistryRepo extracts the repository name from /v2/<name>/tags/list.
func dockerRegistryRepo(path string) string {
	p := strings.TrimPrefix(path, "/v2/")
	if i := strings.LastIndex(p, "/tags/list"); i >= 0 {
		return safe.SanitizeForLog(p[:i])
	}
	return "library/app"
}
