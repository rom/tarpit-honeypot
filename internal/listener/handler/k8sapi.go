package handler

import (
	"bufio"
	"context"
	"net"
	"strings"

	"github.com/rom/tarpit-honeypot/internal/config"
)

// k8sAPI emulates the Kubernetes API server (kube-apiserver, TCP 6443/8080).
// An exposed or anonymously-accessible API server is a full cluster takeover:
// list secrets, create privileged pods, exec into workloads. Scanners sweep
// /version and /api constantly. We answer the unauthenticated discovery probes
// like a real apiserver, capture any Bearer token / client identity, and flag
// the takeover calls (listing secrets, creating pods, exec/attach). Detection
// only; nothing is created.
type k8sAPI struct{}

func (k *k8sAPI) Name() string { return "kubernetes_api" }

func (k *k8sAPI) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
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
		case strings.HasPrefix(lower, "authorization:"):
			authz := strings.TrimSpace(line[14:])
			res.Meta["authorization"] = authz
			if tok := strings.TrimSpace(strings.TrimPrefix(authz, "Bearer")); tok != authz && tok != "" {
				res.Meta["bearer_token"] = tok
				flagAnomaly(&res, "k8s-token-auth")
			}
		case strings.HasPrefix(lower, "user-agent:"):
			res.Meta["user_agent"] = strings.TrimSpace(line[11:])
		}
	}
	res.Meta["method"] = method
	res.Meta["path"] = path

	low := strings.ToLower(path)
	body, status := k.route(method, low, &res)
	resp := "HTTP/1.1 " + status + "\r\n" +
		"Content-Type: application/json\r\n" +
		"Content-Length: " + intToStr(len(body)) + "\r\n" +
		"Connection: close\r\n\r\n" + body
	if _, err := conn.Write([]byte(resp)); err != nil {
		res.Meta["write_err"] = err.Error()
	}
	res.BannerSent = "kubernetes_api " + status
	return res, nil
}

func (k *k8sAPI) route(method, low string, res *Result) (body, status string) {
	status = "200 OK"
	switch {
	case low == "/version" || strings.HasSuffix(low, "/version"):
		body = `{"major":"1","minor":"28","gitVersion":"v1.28.4","platform":"linux/amd64"}`
	case low == "/api" || low == "/api/":
		body = `{"kind":"APIVersions","versions":["v1"],"serverAddressByClientCIDRs":[{"clientCIDR":"0.0.0.0/0","serverAddress":"10.0.0.1:6443"}]}`
	case low == "/apis" || low == "/apis/":
		body = `{"kind":"APIGroupList","groups":[{"name":"apps","versions":[{"groupVersion":"apps/v1","version":"v1"}]},{"name":"rbac.authorization.k8s.io","versions":[{"groupVersion":"rbac.authorization.k8s.io/v1","version":"v1"}]}]}`
	case low == "/healthz" || low == "/livez" || low == "/readyz":
		body = "ok"
	case strings.Contains(low, "/secrets"):
		flagAnomaly(res, "k8s-secret-enum")
		if method == "GET" {
			body = `{"kind":"SecretList","apiVersion":"v1","items":[{"metadata":{"name":"default-token-abc12","namespace":"default"},"type":"kubernetes.io/service-account-token"}]}`
		} else {
			status = "403 Forbidden"
			body = k8sForbidden("secrets")
		}
	case strings.Contains(low, "/pods/") && (strings.Contains(low, "/exec") || strings.Contains(low, "/attach")):
		flagAnomaly(res, "k8s-pod-exec")
		status = "403 Forbidden"
		body = k8sForbidden("pods/exec")
	case method == "POST" && strings.Contains(low, "/pods"):
		flagAnomaly(res, "k8s-pod-create")
		status = "403 Forbidden"
		body = k8sForbidden("pods")
	case strings.Contains(low, "/pods"):
		body = `{"kind":"PodList","apiVersion":"v1","items":[]}`
	default:
		// Anonymous request with no token to a protected path → the real
		// apiserver answers 403 with a system:anonymous message.
		if _, ok := res.Meta["bearer_token"]; !ok {
			status = "403 Forbidden"
			body = `{"kind":"Status","apiVersion":"v1","status":"Failure","message":"forbidden: User \"system:anonymous\" cannot get path","reason":"Forbidden","code":403}`
		} else {
			status = "404 Not Found"
			body = `{"kind":"Status","apiVersion":"v1","status":"Failure","reason":"NotFound","code":404}`
		}
	}
	return
}

func k8sForbidden(resource string) string {
	return `{"kind":"Status","apiVersion":"v1","status":"Failure","message":"` +
		resource + ` is forbidden: User cannot access","reason":"Forbidden","code":403}`
}
