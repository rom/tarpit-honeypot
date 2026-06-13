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

// kubelet emulates the Kubernetes kubelet API (TCP 10250 over TLS; the
// deprecated read-only HTTP port 10255 serves the same read endpoints). An
// anonymously-accessible kubelet is a direct container-RCE surface: /run and
// /exec execute commands inside any pod's container. We answer the read
// endpoints (/pods, /stats, /metrics, /configz) believably — so a scanner
// classifies us as a kubelet and gets pod/container names to target — capture
// the command an attacker tries to run, and flag the run/exec/attach calls as
// RCE. Detection only; nothing is executed.
type kubelet struct{}

func (k *kubelet) Name() string { return "kubelet" }

const kubeletNode = "ip-10-0-1-37"

func (k *kubelet) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	withTimeout(conn, cfg.ReadTimeout)
	res := Result{Meta: map[string]any{}}
	br := bufio.NewReader(conn)
	capN := cfg.ReadBytes
	if capN <= 0 {
		capN = 8192
	}
	head, _ := readHTTPHead(br, capN)
	res.Payload = head

	method, rawPath := "", ""
	for i, line := range strings.Split(string(head), "\r\n") {
		if i == 0 {
			res.Meta["request_line"] = safe.SanitizeForLog(line)
			if f := strings.Fields(line); len(f) >= 2 {
				method, rawPath = strings.ToUpper(f[0]), f[1]
			}
			continue
		}
		lower := strings.ToLower(line)
		switch {
		case strings.HasPrefix(lower, "authorization:"):
			authz := strings.TrimSpace(line[14:])
			if tok := strings.TrimSpace(strings.TrimPrefix(authz, "Bearer")); tok != authz && tok != "" {
				res.Meta["bearer_token"] = safe.SanitizeForLog(tok)
				flagAnomaly(&res, "kubelet-token-auth")
			}
		case strings.HasPrefix(lower, "user-agent:"):
			res.Meta["user_agent"] = safe.SanitizeForLog(strings.TrimSpace(line[11:]))
		}
	}
	res.Meta["method"] = method
	path, query := rawPath, ""
	if i := strings.IndexByte(rawPath, '?'); i >= 0 {
		path, query = rawPath[:i], rawPath[i+1:]
	}
	res.Meta["path"] = safe.SanitizeForLog(path)
	flagAnomaly(&res, "kubelet-access")

	body, ctype, status := k.route(path, query, &res)
	resp := "HTTP/1.1 " + status + "\r\nContent-Type: " + ctype +
		"\r\nContent-Length: " + intToStr(len(body)) + "\r\nConnection: close\r\n\r\n" + body
	if _, err := conn.Write([]byte(resp)); err != nil {
		res.Meta["write_err"] = err.Error()
	}
	res.BannerSent = "kubelet " + status
	return res, nil
}

func (k *kubelet) route(path, query string, res *Result) (body, ctype, status string) {
	ctype, status = "application/json", "200 OK"
	low := strings.ToLower(path)
	switch {
	case low == "/healthz":
		ctype, body = "text/plain", "ok"
	case strings.HasPrefix(low, "/run/"):
		// POST /run/{namespace}/{pod}/{container}?cmd=… — command execution.
		cmd := kubeletQueryCmd(query, "cmd")
		res.Meta["exec_target"] = safe.SanitizeForLog(strings.TrimPrefix(path, "/run/"))
		res.Meta["exec_command"] = safe.SanitizeForLog(cmd)
		flagAnomaly(res, "kubelet-run-exec")
		res.Meta["intent"] = "Kubelet /run — command execution inside a container (RCE): " + safe.SanitizeForLog(cmd)
		ctype, body = "text/plain", kubeletFakeOutput(cmd)
	case strings.HasPrefix(low, "/exec/"):
		cmd := kubeletQueryCmd(query, "command")
		res.Meta["exec_target"] = safe.SanitizeForLog(strings.TrimPrefix(path, "/exec/"))
		res.Meta["exec_command"] = safe.SanitizeForLog(cmd)
		flagAnomaly(res, "kubelet-exec")
		res.Meta["intent"] = "Kubelet /exec — interactive command execution inside a container (RCE): " + safe.SanitizeForLog(cmd)
		ctype, body = "text/plain", ""
	case strings.HasPrefix(low, "/attach/"):
		res.Meta["exec_target"] = safe.SanitizeForLog(strings.TrimPrefix(path, "/attach/"))
		flagAnomaly(res, "kubelet-attach")
		res.Meta["intent"] = "Kubelet /attach — attaching to a container process (RCE)"
		ctype, body = "text/plain", ""
	case low == "/pods" || low == "/pods/" || low == "/runningpods" || low == "/runningpods/":
		flagAnomaly(res, "kubelet-pod-enum")
		setIfEmpty(res.Meta, "intent", "Kubelet pod enumeration — listing pods/containers on the node")
		body = kubeletPodList()
	case strings.HasPrefix(low, "/containerlogs/"):
		flagAnomaly(res, "kubelet-logs")
		res.Meta["intent"] = "Kubelet /containerLogs — reading container logs (exfiltration)"
		ctype, body = "text/plain", "2024-01-01T00:00:00.000000000Z server started, listening on :8080\n"
	case strings.HasPrefix(low, "/stats"):
		flagAnomaly(res, "kubelet-stats")
		setIfEmpty(res.Meta, "intent", "Kubelet /stats — node/pod resource stats (info disclosure)")
		body = `{"node":{"nodeName":"` + kubeletNode + `","cpu":{"usageNanoCores":120000000},"memory":{"usageBytes":2147483648}},"pods":[]}`
	case low == "/configz":
		flagAnomaly(res, "kubelet-configz")
		setIfEmpty(res.Meta, "intent", "Kubelet /configz — reading kubelet configuration (info disclosure)")
		// Advertise the anonymous-AlwaysAllow misconfig the attacker is hunting.
		body = `{"kubeletconfig":{"authentication":{"anonymous":{"enabled":true},"webhook":{"enabled":false}},"authorization":{"mode":"AlwaysAllow"},"readOnlyPort":10255}}`
	case strings.HasPrefix(low, "/metrics"):
		ctype, body = "text/plain", "# HELP kubelet_running_pods Number of pods\n# TYPE kubelet_running_pods gauge\nkubelet_running_pods 3\n"
	case strings.HasPrefix(low, "/spec"):
		body = `{"num_cores":4,"memory_capacity":8262463488,"machine_id":"a1b2c3d4e5f6"}`
	default:
		status, ctype, body = "404 Not Found", "text/plain", "404 page not found"
	}
	return
}

// kubeletQueryCmd extracts the command from a /run (?cmd=…) or /exec
// (?command=…&command=…) query string.
func kubeletQueryCmd(query, key string) string {
	v, err := url.ParseQuery(query)
	if err != nil {
		return ""
	}
	if key == "command" {
		return strings.Join(v["command"], " ")
	}
	return v.Get(key)
}

// kubeletFakeOutput returns believable stdout for common recon commands so an
// attacker thinks the /run RCE landed and keeps probing (capturing more).
func kubeletFakeOutput(cmd string) string {
	has := func(word string) bool {
		for _, f := range strings.Fields(cmd) {
			if f == word || strings.HasSuffix(f, "/"+word) {
				return true
			}
		}
		return false
	}
	switch {
	case strings.Contains(cmd, "/etc/passwd"):
		return "root:x:0:0:root:/root:/bin/bash\nnobody:x:65534:65534:Kernel Overflow User:/:/usr/sbin/nologin\n"
	case has("whoami"):
		return "root\n"
	case has("id"):
		return "uid=0(root) gid=0(root) groups=0(root)\n"
	case has("hostname"):
		return kubeletNode + "\n"
	case has("uname"):
		return "Linux " + kubeletNode + " 5.15.0 #1 SMP x86_64 GNU/Linux\n"
	case has("env") || strings.Contains(cmd, "printenv"):
		return "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n" +
			"KUBERNETES_SERVICE_HOST=10.96.0.1\nKUBERNETES_SERVICE_PORT=443\n"
	case has("ls"):
		return "bin\nboot\ndev\netc\nhome\nlib\nproc\nroot\nrun\nsbin\nsys\ntmp\nusr\nvar\n"
	}
	return ""
}

func kubeletPodList() string {
	return `{"kind":"PodList","apiVersion":"v1","items":[` +
		`{"metadata":{"name":"kube-proxy-7xq2v","namespace":"kube-system"},"spec":{"containers":[{"name":"kube-proxy","image":"registry.k8s.io/kube-proxy:v1.28.4"}]},"status":{"phase":"Running","hostIP":"10.0.1.37"}},` +
		`{"metadata":{"name":"coredns-5dd5756b68-abcde","namespace":"kube-system"},"spec":{"containers":[{"name":"coredns","image":"registry.k8s.io/coredns/coredns:v1.10.1"}]},"status":{"phase":"Running","podIP":"10.244.0.5"}},` +
		`{"metadata":{"name":"web-app-6f4c9d8b7-mn4kp","namespace":"default"},"spec":{"containers":[{"name":"web","image":"nginx:1.25"}]},"status":{"phase":"Running","podIP":"10.244.0.12"}}` +
		`]}`
}
