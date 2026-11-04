package handler

import (
	"bufio"
	"context"
	"net"
	"strings"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/cve"
	"github.com/rom/tarpit-honeypot/internal/safe"
)

// Cloud-native / DevOps exposed-service decoys. Each of these ships an
// unauthenticated HTTP control plane that, left on the internet, is an RCE or
// data-theft foothold and a favourite cryptojacking entry point. The handler
// fingerprints the service so a scanner records it as live, captures the
// request, and flags the hands-on-keyboard steps (job/kernel/session spawn,
// service-register-with-script, SQL over HTTP, creds-disclosure probe). Nothing
// is ever executed.
//
//	jupyter    (8888)  Jupyter Notebook/Lab — token-less access, terminal/kernel RCE
//	selenium   (4444)  Selenium Grid/standalone — node RCE / chrome binary override (cryptojacking)
//	consul     (8500)  HashiCorp Consul HTTP API — catalog/KV enum, health-check script RCE
//	nomad      (4646)  HashiCorp Nomad HTTP API — raw_exec job-submission RCE
//	minio      (9000)  MinIO S3 — bucket enum + CVE-2023-28432 env-creds disclosure
//	clickhouse (8123)  ClickHouse HTTP — SQL over HTTP, file()/url() read/SSRF
type cloudsvc struct{ kind string }

func (h *cloudsvc) Name() string { return h.kind }

func (h *cloudsvc) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	withTimeout(conn, cfg.ReadTimeout)
	res := Result{Meta: map[string]any{}}
	br := bufio.NewReader(conn)
	capN := cfg.ReadBytes
	if capN <= 0 {
		capN = 8192
	}
	head, _ := readHTTPHead(br, capN)
	res.Payload = head
	method, path, query, authz, ua := svcHTTPReqLine(head)
	res.Meta["method"] = method
	res.Meta["path"] = safe.SanitizeForLog(path)
	if ua != "" {
		res.Meta["user_agent"] = safe.SanitizeForLog(ua)
	}
	flagAnomaly(&res, h.kind+"-probe")
	if u, p, ok := decodeBasic(authz); ok {
		res.Meta["basic_user"] = safe.SanitizeForLog(u)
		res.Meta["basic_pass"] = safe.SanitizeForLog(p)
		flagDefaultCred(&res, u, p)
	}
	var body []byte
	if method == "POST" || method == "PUT" {
		body = svcHTTPBody(br, head, capN)
		res.Payload = append(res.Payload, body...)
	}

	status, server, ctype, respBody := "200 OK", "Server\r\n", "application/json", "{}"
	switch h.kind {
	case "jupyter":
		server, ctype, respBody = h.jupyter(method, path, query, &res)
	case "selenium":
		server, ctype, respBody = h.selenium(method, path, string(body), &res)
	case "consul":
		server, ctype, respBody = h.consul(method, path, query, string(body), &res)
	case "nomad":
		server, ctype, respBody = h.nomad(method, path, string(body), &res)
	case "minio":
		status, server, ctype, respBody = h.minio(method, path, &res)
	case "clickhouse":
		server, ctype, respBody = h.clickhouse(method, path, query, string(body), &res)
	}

	// Shared HTTP exploit corpus (SSRF / traversal / log4shell etc. arrive here too).
	for _, rec := range cve.MatchPayload("http", string(res.Payload)) {
		res.CVEHits = appendUnique(res.CVEHits, rec.ID)
		flagAnomaly(&res, "cve:"+rec.ID)
	}

	if _, err := conn.Write([]byte(svcHTTPResp(status, server, ctype, respBody))); err != nil {
		res.Meta["write_err"] = err.Error()
	}
	res.BannerSent = h.kind + " " + status
	return res, nil
}

func (h *cloudsvc) jupyter(method, path, query string, res *Result) (server, ctype, body string) {
	server = "Server: TornadoServer/6.4\r\n"
	low := strings.ToLower(path)
	switch {
	case path == "/" || low == "/tree" || low == "/lab" || strings.HasPrefix(low, "/tree") || strings.HasPrefix(low, "/lab"):
		if !strings.Contains(query, "token=") {
			flagAnomaly(res, "jupyter-unauth-access")
			setIfEmpty(res.Meta, "intent", "Jupyter accessed without a token — exposed notebook (RCE foothold)")
		}
		return server, "text/html; charset=UTF-8", "<html><head><title>JupyterLab</title></head><body>JupyterLab 4.2.0</body></html>"
	case strings.HasPrefix(low, "/api/terminals"):
		if method == "POST" {
			flagAnomaly(res, "jupyter-terminal-rce")
			res.Meta["intent"] = "Jupyter terminal spawn — interactive OS shell on an exposed notebook"
		}
		return server, "application/json", `[{"name":"1"}]`
	case strings.HasPrefix(low, "/api/kernels"):
		if method == "POST" {
			flagAnomaly(res, "jupyter-kernel-spawn")
			res.Meta["intent"] = "Jupyter kernel spawn — arbitrary code execution on an exposed notebook"
		} else {
			flagAnomaly(res, "jupyter-enumeration")
		}
		return server, "application/json", `[]`
	case strings.HasPrefix(low, "/api/sessions"), strings.HasPrefix(low, "/api/contents"):
		flagAnomaly(res, "jupyter-enumeration")
		return server, "application/json", `[]`
	}
	return server, "application/json", `{"version":"2.14.0"}`
}

func (h *cloudsvc) selenium(method, path, body string, res *Result) (server, ctype, respBody string) {
	server = "Server: Jetty\r\n"
	low := strings.ToLower(path)
	switch {
	case strings.Contains(low, "/status"):
		flagAnomaly(res, "selenium-grid-probe")
		setIfEmpty(res.Meta, "intent", "Selenium Grid status probe — fingerprinting an exposed grid")
		return server, "application/json", `{"value":{"ready":true,"message":"Selenium Grid ready.","nodes":[]}}`
	case strings.Contains(low, "/session") && method == "POST":
		flagAnomaly(res, "selenium-session-create")
		lb := strings.ToLower(body)
		// A Chrome capability that overrides the browser binary or passes CLI
		// args is the node-RCE / arbitrary-binary-execution vector abused for
		// cryptojacking on exposed grids.
		if strings.Contains(lb, "goog:chromeoptions") && (strings.Contains(lb, "\"binary\"") || strings.Contains(lb, "\"args\"")) {
			flagAnomaly(res, "selenium-node-rce")
			res.Meta["intent"] = "Selenium node RCE — chromeOptions binary/args override on an exposed grid"
		}
		return server, "application/json", `{"value":{"sessionId":"0","capabilities":{}}}`
	case strings.Contains(low, "/graphql"):
		flagAnomaly(res, "selenium-grid-probe")
		return server, "application/json", `{"data":{"grid":{"version":"4.21.0"}}}`
	}
	return server, "application/json", `{"value":{}}`
}

func (h *cloudsvc) consul(method, path, query, body string, res *Result) (server, ctype, respBody string) {
	server = "Server\r\nX-Consul-Index: 1\r\n"
	low := strings.ToLower(path)
	switch {
	case strings.Contains(low, "/v1/agent/service/register"):
		flagAnomaly(res, "consul-service-register")
		lb := strings.ToLower(body)
		// A registered service/health check carrying a shell "args"/"script" is
		// remote code execution on every agent that runs the check.
		if strings.Contains(lb, "\"args\"") || strings.Contains(lb, "\"script\"") {
			flagAnomaly(res, "consul-service-register-rce")
			res.Meta["intent"] = "Consul service register with a check script/args — RCE on agents (exposed Consul)"
		}
		return server, "application/json", `true`
	case strings.Contains(low, "/v1/kv/"):
		flagAnomaly(res, "consul-kv-access")
		if strings.Contains(strings.ToLower(query), "recurse") {
			res.Meta["intent"] = "Consul KV recursive read — secrets enumeration on an exposed Consul"
		}
		return server, "application/json", `[]`
	case strings.Contains(low, "/v1/catalog"), strings.Contains(low, "/v1/agent/self"), strings.Contains(low, "/v1/agent/members"):
		flagAnomaly(res, "consul-enumeration")
		setIfEmpty(res.Meta, "intent", "Consul catalog/agent enumeration (exposed Consul HTTP API)")
		return server, "application/json", `{"Config":{"Datacenter":"dc1","Server":true}}`
	}
	return server, "application/json", `{}`
}

func (h *cloudsvc) nomad(method, path, body string, res *Result) (server, ctype, respBody string) {
	server = "Server\r\n"
	low := strings.ToLower(path)
	switch {
	case strings.Contains(low, "/v1/jobs") && (method == "POST" || method == "PUT"), strings.Contains(low, "/v1/job/"):
		flagAnomaly(res, "nomad-job-submit")
		lb := strings.ToLower(body)
		// raw_exec / exec drivers run arbitrary commands on the client nodes.
		if strings.Contains(lb, "raw_exec") || strings.Contains(lb, "\"driver\":\"exec\"") || strings.Contains(lb, "\"command\"") {
			flagAnomaly(res, "nomad-job-submit-rce")
			res.Meta["intent"] = "Nomad job submission with raw_exec/exec driver — RCE on client nodes (exposed Nomad)"
		}
		return server, "application/json", `{"EvalID":"0"}`
	case strings.Contains(low, "/v1/agent/self"), strings.Contains(low, "/v1/nodes"), strings.Contains(low, "/v1/jobs"):
		flagAnomaly(res, "nomad-enumeration")
		setIfEmpty(res.Meta, "intent", "Nomad agent/node/job enumeration (exposed Nomad HTTP API)")
		return server, "application/json", `{"config":{"Region":"global"}}`
	}
	return server, "application/json", `{}`
}

func (h *cloudsvc) minio(method, path string, res *Result) (status, server, ctype, body string) {
	server = "Server: MinIO\r\n"
	low := strings.ToLower(path)
	switch {
	case strings.Contains(low, "/minio/bootstrap/v1/verify"):
		// CVE-2023-28432: unauthenticated POST leaks the server's environment
		// (including MINIO_SECRET_KEY) in cluster-deploy mode.
		flagAnomaly(res, "minio-bootstrap-verify")
		res.CVEHits = appendUnique(res.CVEHits, "CVE-2023-28432")
		flagAnomaly(res, "cve:CVE-2023-28432")
		res.Meta["intent"] = "MinIO bootstrap verify — unauthenticated environment/credential disclosure (CVE-2023-28432)"
		return "200 OK", server, "application/json", `{"MinioEnv":{}}`
	case strings.Contains(low, "/minio/health"):
		return "200 OK", server, "application/json", `{}`
	case path == "/" || path == "":
		flagAnomaly(res, "minio-bucket-enum")
		setIfEmpty(res.Meta, "intent", "MinIO S3 ListBuckets — bucket enumeration on an exposed MinIO")
		return "200 OK", server, "application/xml",
			`<?xml version="1.0" encoding="UTF-8"?><ListAllMyBucketsResult><Buckets></Buckets></ListAllMyBucketsResult>`
	}
	return "403 Forbidden", server, "application/xml",
		`<?xml version="1.0" encoding="UTF-8"?><Error><Code>AccessDenied</Code></Error>`
}

func (h *cloudsvc) clickhouse(method, path, query, body string, res *Result) (server, ctype, respBody string) {
	server = "Server\r\nX-ClickHouse-Server-Display-Name: clickhouse\r\n"
	q := query
	if body != "" {
		q = q + "\n" + body
	}
	ql := strings.ToLower(q)
	if path == "/" && q == "" {
		return server, "text/plain; charset=UTF-8", "Ok.\n"
	}
	if strings.Contains(ql, "query=") || method == "POST" || strings.Contains(ql, "select") {
		flagAnomaly(res, "clickhouse-sql-exec")
		setIfEmpty(res.Meta, "intent", "ClickHouse SQL over HTTP (exposed HTTP interface)")
		// file()/url()/remote() table functions = local file read / SSRF.
		if strings.Contains(ql, "file(") || strings.Contains(ql, "url(") || strings.Contains(ql, "remote(") {
			flagAnomaly(res, "clickhouse-file-read")
			res.Meta["intent"] = "ClickHouse file()/url()/remote() table function — file read / SSRF"
		}
		// system.* reads enumerate users, settings, and config.
		if strings.Contains(ql, "system.") {
			flagAnomaly(res, "clickhouse-system-table-read")
		}
	}
	return server, "text/tab-separated-values", ""
}
