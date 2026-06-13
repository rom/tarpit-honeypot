package handler

import (
	"net/url"
	"strings"
	"testing"
)

func svcReq(method, path, body string) string {
	h := method + " " + path + " HTTP/1.1\r\nHost: svc\r\n"
	if body != "" {
		h += "Content-Length: " + intToStr(len(body)) + "\r\n"
	}
	return h + "\r\n" + body
}

// --- Docker Registry v2 ---

func TestDockerRegistryFingerprint(t *testing.T) {
	_, out := roundtrip(t, &dockerRegistry{}, svcReq("GET", "/v2/", ""))
	if !strings.Contains(string(out), "Docker-Distribution-Api-Version: registry/2.0") {
		t.Errorf("missing registry fingerprint header: %q", out)
	}
}

func TestDockerRegistryCatalog(t *testing.T) {
	res, out := roundtrip(t, &dockerRegistry{}, svcReq("GET", "/v2/_catalog", ""))
	if !hasAnom(res, "docker-registry-catalog") {
		t.Errorf("catalog enumeration not flagged: %v", res.Meta["anomalies"])
	}
	if !strings.Contains(string(out), `"repositories"`) {
		t.Errorf("catalog response missing repositories: %q", out)
	}
}

// --- CouchDB ---

func TestCouchDBWelcome(t *testing.T) {
	_, out := roundtrip(t, &couchdb{}, svcReq("GET", "/", ""))
	if !strings.Contains(string(out), `"couchdb":"Welcome"`) {
		t.Errorf("welcome banner missing: %q", out)
	}
}

func TestCouchDBRoleInjectionCVE(t *testing.T) {
	body := `{"type":"user","name":"oops","roles":["_admin"],"roles":[],"password":"x"}`
	res, _ := roundtrip(t, &couchdb{}, svcReq("PUT", "/_users/org.couchdb.user:oops", body))
	if !hasAnom(res, "cve:CVE-2017-12635") || !cveHit(res, "CVE-2017-12635") {
		t.Errorf("CVE-2017-12635 role injection not flagged: %v", res.Meta["anomalies"])
	}
}

func TestCouchDBSessionCreds(t *testing.T) {
	res, _ := roundtrip(t, &couchdb{}, svcReq("POST", "/_session", "name=admin&password=hunter2"))
	if res.Meta["auth_user"] != "admin" || res.Meta["auth_pass"] != "hunter2" {
		t.Errorf("session creds not captured: %v / %v", res.Meta["auth_user"], res.Meta["auth_pass"])
	}
	if !hasAnom(res, "couchdb-credential-attempt") {
		t.Errorf("credential attempt not flagged")
	}
}

// --- InfluxDB ---

func TestInfluxDBPing(t *testing.T) {
	_, out := roundtrip(t, &influxdb{}, svcReq("GET", "/ping", ""))
	s := string(out)
	if !strings.Contains(s, "X-Influxdb-Version") || !strings.Contains(s, "204 No Content") {
		t.Errorf("/ping fingerprint wrong: %q", s)
	}
}

func TestInfluxDBSetupTakeover(t *testing.T) {
	body := `{"username":"admin","password":"supersecret","org":"acme","bucket":"default"}`
	res, _ := roundtrip(t, &influxdb{}, svcReq("POST", "/api/v2/setup", body))
	if !hasAnom(res, "influxdb-setup-takeover") {
		t.Errorf("setup takeover not flagged: %v", res.Meta["anomalies"])
	}
	if res.Meta["auth_user"] != "admin" || res.Meta["auth_pass"] != "supersecret" {
		t.Errorf("setup creds not captured: %v / %v", res.Meta["auth_user"], res.Meta["auth_pass"])
	}
}

func TestInfluxDBQueryCreds(t *testing.T) {
	res, _ := roundtrip(t, &influxdb{}, svcReq("GET", "/query?u=root&p=root&q="+url.QueryEscape("SHOW DATABASES"), ""))
	if res.Meta["auth_user"] != "root" || res.Meta["auth_pass"] != "root" {
		t.Errorf("query creds not captured: %v / %v", res.Meta["auth_user"], res.Meta["auth_pass"])
	}
	if !hasAnom(res, "influxdb-query") {
		t.Errorf("query not flagged")
	}
	if res.Meta["influxql"] != "SHOW DATABASES" {
		t.Errorf("InfluxQL not captured: %v", res.Meta["influxql"])
	}
}
