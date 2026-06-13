package handler

import (
	"bufio"
	"context"
	"net"
	"net/url"
	"strings"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/safe"
)

// influxdb emulates InfluxDB's HTTP API (TCP 8086). /ping + the
// X-Influxdb-Version header is the fingerprint. The high-value surface is the
// v2 /api/v2/setup endpoint: on a fresh, unauthenticated instance it creates
// the initial admin org/user/token — an instant takeover. We also capture the
// v1 /query credentials (u=/p=) and the v2 Authorization token. We answer the
// probes believably, capture the credentials/setup attempt, and store nothing.
type influxdb struct{}

func (i *influxdb) Name() string { return "influxdb" }

func (i *influxdb) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
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
	if tok := strings.TrimSpace(strings.TrimPrefix(authz, "Token")); tok != authz && tok != "" {
		res.Meta["influx_token"] = safe.SanitizeForLog(tok)
		flagAnomaly(&res, "influxdb-token-auth")
	}
	flagAnomaly(&res, "influxdb-access")

	const verHdr = "X-Influxdb-Version: 2.7.1\r\nX-Influxdb-Build: OSS\r\n"
	low := strings.ToLower(path)
	ctype, status, body, extra := "application/json", "200 OK", "", verHdr
	switch {
	case low == "/ping":
		setIfEmpty(res.Meta, "intent", "InfluxDB /ping — fingerprinting the database")
		status, body = "204 No Content", ""
	case low == "/api/v2/setup":
		// Unauthenticated initial setup = full takeover.
		b := svcHTTPBody(br, head, capN)
		res.Payload = append(res.Payload, b...)
		if u := jsonStrField(string(b), "username"); u != "" {
			res.Meta["auth_user"] = safe.SanitizeForLog(u)
			res.Meta["auth_pass"] = safe.SanitizeForLog(jsonStrField(string(b), "password"))
			res.Meta["setup_org"] = safe.SanitizeForLog(jsonStrField(string(b), "org"))
		}
		flagAnomaly(&res, "influxdb-setup-takeover")
		res.Meta["intent"] = "InfluxDB /api/v2/setup — initial-admin creation on an unauthenticated instance (takeover)"
		body = `{"user":{"id":"0a1b2c3d4e5f6071","name":"` + safe.SanitizeForLog(jsonStrField(string(b), "username")) + `"},"org":{"id":"7a1b2c3d4e5f6071"},"bucket":{"id":"8a1b2c3d4e5f6071"},"auth":{"token":"sometoken-not-real"}}`
	case low == "/query":
		u, p, q := influxQueryParams(query)
		if u != "" || p != "" {
			res.Meta["auth_user"] = safe.SanitizeForLog(u)
			res.Meta["auth_pass"] = safe.SanitizeForLog(p)
			flagAnomaly(&res, "influxdb-credential-attempt")
			flagDefaultCred(&res, u, p)
		}
		if q != "" {
			res.Meta["influxql"] = safe.SanitizeForLog(q)
		}
		flagAnomaly(&res, "influxdb-query")
		setIfEmpty(res.Meta, "intent", "InfluxDB /query — InfluxQL against the database")
		body = `{"results":[{"statement_id":0,"series":[]}]}`
	case low == "/write" || strings.HasPrefix(low, "/api/v2/write"):
		u, p, _ := influxQueryParams(query)
		if u != "" || p != "" {
			res.Meta["auth_user"] = safe.SanitizeForLog(u)
			res.Meta["auth_pass"] = safe.SanitizeForLog(p)
			flagDefaultCred(&res, u, p)
		}
		flagAnomaly(&res, "influxdb-write")
		setIfEmpty(res.Meta, "intent", "InfluxDB write — ingesting line-protocol data")
		status, body = "204 No Content", ""
	case strings.HasPrefix(low, "/api/v2/"):
		flagAnomaly(&res, "influxdb-v2-api")
		setIfEmpty(res.Meta, "intent", "InfluxDB v2 API access ("+safe.SanitizeForLog(path)+")")
		body = `{"links":{"self":"/api/v2"}}`
	default:
		status, ctype, body = "404 Not Found", "application/json", `{"code":"not found","message":"path not found"}`
	}

	if _, err := conn.Write([]byte(svcHTTPResp(status, extra, ctype, body))); err != nil {
		res.Meta["write_err"] = err.Error()
	}
	res.BannerSent = "influxdb " + status
	return res, nil
}

// influxQueryParams pulls the InfluxDB v1 credentials (u/p) and query (q) from
// a query string.
func influxQueryParams(query string) (user, pass, q string) {
	v, err := url.ParseQuery(query)
	if err != nil {
		return "", "", ""
	}
	return v.Get("u"), v.Get("p"), v.Get("q")
}
