package handler

import (
	"strings"
	"testing"
)

func kubeReq(t *testing.T, reqLine string) (Result, string) {
	t.Helper()
	res, out := roundtrip(t, &kubelet{}, reqLine+" HTTP/1.1\r\nHost: node:10250\r\n\r\n")
	return res, string(out)
}

// GET /pods enumerates pods/containers and is flagged.
func TestKubeletPodEnum(t *testing.T) {
	res, out := kubeReq(t, "GET /pods")
	if !hasAnom(res, "kubelet-pod-enum") {
		t.Errorf("pod enumeration not flagged: %v", res.Meta["anomalies"])
	}
	if !strings.Contains(out, "web-app-6f4c9d8b7-mn4kp") {
		t.Errorf("pod list missing the expected pod: %q", out)
	}
}

// POST /run captures the command and is flagged as RCE, with believable output.
func TestKubeletRunExec(t *testing.T) {
	res, out := kubeReq(t, "POST /run/default/web-app-6f4c9d8b7-mn4kp/web?cmd=id")
	if !hasAnom(res, "kubelet-run-exec") {
		t.Errorf("/run not flagged as RCE: %v", res.Meta["anomalies"])
	}
	if res.Meta["exec_command"] != "id" {
		t.Errorf("command not captured: %v", res.Meta["exec_command"])
	}
	if !strings.Contains(out, "uid=0(root)") {
		t.Errorf("/run did not return a believable root id output: %q", out)
	}
}

// /exec captures a multi-arg command.
func TestKubeletExecCommandCapture(t *testing.T) {
	res, _ := kubeReq(t, "GET /exec/default/web-app-6f4c9d8b7-mn4kp/web?command=cat&command=/etc/shadow")
	if !hasAnom(res, "kubelet-exec") {
		t.Errorf("/exec not flagged: %v", res.Meta["anomalies"])
	}
	if res.Meta["exec_command"] != "cat /etc/shadow" {
		t.Errorf("exec command not captured: %v", res.Meta["exec_command"])
	}
}

// /configz advertises the anonymous-AlwaysAllow misconfig as bait.
func TestKubeletConfigz(t *testing.T) {
	res, out := kubeReq(t, "GET /configz")
	if !hasAnom(res, "kubelet-configz") {
		t.Errorf("/configz not flagged: %v", res.Meta["anomalies"])
	}
	if !strings.Contains(out, `"anonymous":{"enabled":true}`) || !strings.Contains(out, "AlwaysAllow") {
		t.Errorf("/configz did not advertise the anonymous misconfig: %q", out)
	}
}
