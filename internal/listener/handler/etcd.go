package handler

import (
	"bufio"
	"bytes"
	"context"
	"net"
	"strings"

	"github.com/rom/tarpit-honeypot/internal/config"
)

// etcd emulates the etcd key-value store HTTP API (TCP 2379). An exposed,
// unauthenticated etcd is a jackpot: in a Kubernetes cluster it holds every
// Secret, ServiceAccount token and the whole cluster state. Scanners sweep
// 2379 constantly. We answer the version/health probes like a real etcd and,
// for the v2 keys API and v3 range RPC, return believable cluster data —
// flagging any attempt to read secrets or write/delete keys (the takeover
// TTP). Detection only; nothing is persisted.
type etcd struct{}

func (e *etcd) Name() string { return "etcd" }

func (e *etcd) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	withTimeout(conn, cfg.ReadTimeout)
	res := Result{Meta: map[string]any{}}
	br := bufio.NewReader(conn)
	capN := cfg.ReadBytes
	if capN <= 0 {
		capN = 8192
	}
	// Read headers; capture a bounded body too (v3 range RPCs POST JSON).
	var buf bytes.Buffer
	headersDone := false
	for buf.Len() < capN {
		b, err := br.ReadByte()
		if err != nil {
			break
		}
		buf.WriteByte(b)
		if !headersDone && bytes.HasSuffix(buf.Bytes(), []byte("\r\n\r\n")) {
			headersDone = true
			// Drain whatever body bytes are already buffered, then stop.
			for br.Buffered() > 0 && buf.Len() < capN {
				nb, err := br.ReadByte()
				if err != nil {
					break
				}
				buf.WriteByte(nb)
			}
			break
		}
	}
	res.Payload = buf.Bytes()

	method, path := "", ""
	bodyStart := bytes.Index(buf.Bytes(), []byte("\r\n\r\n"))
	reqBody := ""
	if bodyStart >= 0 {
		reqBody = string(buf.Bytes()[bodyStart+4:])
	}
	for i, line := range strings.Split(buf.String(), "\r\n") {
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
		case strings.HasPrefix(lower, "authorization:"):
			res.Meta["authorization"] = strings.TrimSpace(line[14:])
		case strings.HasPrefix(lower, "user-agent:"):
			res.Meta["user_agent"] = strings.TrimSpace(line[11:])
		}
	}
	res.Meta["method"] = method
	res.Meta["path"] = path

	low := strings.ToLower(path)
	body, contentType, status := e.route(method, low, reqBody, &res)

	resp := "HTTP/1.1 " + status + "\r\n" +
		"Content-Type: " + contentType + "\r\n" +
		"X-Etcd-Cluster-Id: 7e27652122e8b2ae\r\n" +
		"X-Etcd-Index: 4711\r\n" +
		"Content-Length: " + intToStr(len(body)) + "\r\n" +
		"Connection: close\r\n\r\n" +
		body
	if _, err := conn.Write([]byte(resp)); err != nil {
		res.Meta["write_err"] = err.Error()
	}
	res.BannerSent = "etcd " + status
	return res, nil
}

func (e *etcd) route(method, low, reqBody string, res *Result) (body, contentType, status string) {
	contentType = "application/json"
	status = "200 OK"

	// A v3 range request body that targets the secret prefix, or a v2 read of
	// a secret/token key, is credential theft.
	bodyLow := strings.ToLower(reqBody)
	secretTouch := strings.Contains(low, "/secret") || strings.Contains(low, "token") ||
		strings.Contains(bodyLow, "secret") || strings.Contains(bodyLow, "/registry/secrets")

	switch {
	case strings.HasPrefix(low, "/version"):
		body = `{"etcdserver":"3.5.9","etcdcluster":"3.5.0"}`
	case strings.HasPrefix(low, "/health"):
		body = `{"health":"true","reason":""}`
	case strings.HasPrefix(low, "/v3/kv/range") || strings.HasPrefix(low, "/v3beta/kv/range") ||
		strings.HasPrefix(low, "/v3alpha/kv/range"):
		if secretTouch {
			flagAnomaly(res, "etcd-secret-read")
		} else {
			flagAnomaly(res, "etcd-range-read")
		}
		// key = base64("/registry/secrets/default/default-token"); value is a
		// believable (synthetic) service-account JWT, base64'd — no "honey" tell,
		// so a scanner reading the KV can't distinguish it from a real etcd.
		body = `{"header":{"cluster_id":9081764229861876650,"member_id":12345,"revision":4711,"raft_term":2},"kvs":[{"key":"L3JlZ2lzdHJ5L3NlY3JldHMvZGVmYXVsdC9kZWZhdWx0LXRva2Vu","create_revision":2,"mod_revision":2,"version":1,"value":"ZXlKaGJHY2lPaUpTVXpJMU5pSjkuZXlKemRXSWlPaUp6ZVhOMFpXMDZjMkVpZlEuS3A5bVpxM3ZSN3dMczF4Tg=="}],"count":1}`
	case strings.HasPrefix(low, "/v3/kv/put") || strings.HasPrefix(low, "/v3/kv/deleterange"):
		flagAnomaly(res, "etcd-write")
		body = `{"header":{"cluster_id":9081764229861876650,"member_id":12345,"revision":4712,"raft_term":2}}`
	case strings.HasPrefix(low, "/v2/keys"):
		if method == "GET" {
			if secretTouch {
				flagAnomaly(res, "etcd-secret-read")
			}
			body = `{"action":"get","node":{"key":"/registry","dir":true,"nodes":[{"key":"/registry/secrets","dir":true,"modifiedIndex":2,"createdIndex":2}],"modifiedIndex":1,"createdIndex":1}}`
		} else if method == "PUT" || method == "POST" || method == "DELETE" {
			flagAnomaly(res, "etcd-write")
			body = `{"action":"set","node":{"key":"/x","value":"","modifiedIndex":4712,"createdIndex":4712}}`
		} else {
			status = "405 Method Not Allowed"
			body = `{"errorCode":405,"message":"Method Not Allowed"}`
		}
	case strings.HasPrefix(low, "/v2/members") || strings.HasPrefix(low, "/v3/cluster/member/list"):
		body = `{"members":[{"id":"7e27652122e8b2ae","name":"etcd-0","peerURLs":["http://10.0.0.42:2380"],"clientURLs":["http://10.0.0.42:2379"]}]}`
	case strings.HasPrefix(low, "/metrics"):
		contentType = "text/plain"
		body = "# HELP etcd_server_has_leader Whether or not a leader exists.\netcd_server_has_leader 1\n"
	default:
		status = "404 Not Found"
		body = `{"errorCode":100,"message":"Key not found"}`
	}
	return
}
