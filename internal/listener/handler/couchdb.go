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

// couchdb emulates Apache CouchDB (TCP 5984). Exposed CouchDB is a classic
// data-theft + takeover target: the welcome banner fingerprints it, /_all_dbs
// enumerates databases, /_session takes a login (cleartext name/password), and
// a PUT to /_users carrying an "_admin" role is the CVE-2017-12635 privilege-
// escalation ("admin party"). We answer the probes believably, capture the
// credential, flag the takeover attempt, and store nothing.
type couchdb struct{}

func (c *couchdb) Name() string { return "couchdb" }

func (c *couchdb) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
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
	if u, p, ok := decodeBasic(authz); ok {
		res.Meta["basic_user"] = safe.SanitizeForLog(u)
		res.Meta["basic_pass"] = safe.SanitizeForLog(p)
		flagDefaultCred(&res, u, p)
	}
	flagAnomaly(&res, "couchdb-access")

	low := strings.ToLower(path)
	ctype, status, body := "application/json", "200 OK", ""
	switch {
	case path == "/" || path == "":
		setIfEmpty(res.Meta, "intent", "CouchDB welcome probe — fingerprinting the database")
		body = `{"couchdb":"Welcome","version":"3.3.2","git_sha":"11a234070","uuid":"a1b2c3d4e5f60718a1b2c3d4e5f60718","features":["access-ready","partitioned","pluggable-storage-engines","reshard","scheduler"],"vendor":{"name":"The Apache Software Foundation"}}`
	case low == "/_all_dbs":
		flagAnomaly(&res, "couchdb-db-enum")
		res.Meta["intent"] = "CouchDB _all_dbs — enumerating databases (info disclosure)"
		body = `["_global_changes","_replicator","_users","app_data","sessions"]`
	case low == "/_session":
		c.session(br, head, capN, query, &res)
		status, body = "200 OK", `{"ok":true,"name":null,"roles":[]}`
	case strings.HasPrefix(low, "/_users") || strings.HasPrefix(low, "/_node"):
		// PUT/POST to _users carrying an _admin role is CVE-2017-12635.
		bodyBytes := svcHTTPBody(br, head, capN)
		res.Payload = append(res.Payload, bodyBytes...)
		lb := strings.ToLower(string(bodyBytes))
		if (method == "PUT" || method == "POST") && strings.Contains(lb, "roles") && strings.Contains(lb, "_admin") {
			res.CVEHits = appendUnique(res.CVEHits, "CVE-2017-12635")
			flagAnomaly(&res, "cve:CVE-2017-12635")
			res.Meta["intent"] = "CouchDB _users role injection — privilege escalation to admin (CVE-2017-12635)"
		} else {
			flagAnomaly(&res, "couchdb-admin-access")
			setIfEmpty(res.Meta, "intent", "CouchDB admin/_users access")
		}
		body = `{"ok":true}`
	case low == "/_config" || strings.Contains(low, "/_config"):
		flagAnomaly(&res, "couchdb-config-access")
		res.Meta["intent"] = "CouchDB _config — reading server configuration / admin hashes (info disclosure)"
		body = `{"admins":{},"chttpd":{"bind_address":"0.0.0.0","port":"5984"},"httpd":{"authentication_handlers":"{couch_httpd_auth, cookie_authentication_handler}"}}`
	case strings.HasSuffix(low, "/_all_docs"):
		flagAnomaly(&res, "couchdb-doc-enum")
		setIfEmpty(res.Meta, "intent", "CouchDB _all_docs — enumerating documents")
		body = `{"total_rows":0,"offset":0,"rows":[]}`
	default:
		if method == "GET" && low != "/favicon.ico" && !strings.HasPrefix(low, "/_") {
			// A database info request.
			body = `{"db_name":"` + couchDBName(path) + `","doc_count":0,"update_seq":"0"}`
		} else {
			status, ctype = "404 Object Not Found", "application/json"
			body = `{"error":"not_found","reason":"Database does not exist."}`
		}
	}
	// CouchDB also matches the generic HTTP CVE corpus (e.g. proxy/SSRF probes).
	for _, rec := range cve.MatchPayload("http", string(head)) {
		res.CVEHits = appendUnique(res.CVEHits, rec.ID)
		flagAnomaly(&res, "cve:"+rec.ID)
	}

	if _, err := conn.Write([]byte(svcHTTPResp(status, "Server: CouchDB/3.3.2 (Erlang OTP/24)\r\n", ctype, body))); err != nil {
		res.Meta["write_err"] = err.Error()
	}
	res.BannerSent = "couchdb " + status
	return res, nil
}

// session captures the login from a POST /_session (form or JSON body).
func (c *couchdb) session(br *bufio.Reader, head []byte, capN int, query string, res *Result) {
	body := svcHTTPBody(br, head, capN)
	res.Payload = append(res.Payload, body...)
	name, pass := couchSessionCreds(string(body))
	if name == "" {
		name, pass = couchSessionCreds(query)
	}
	if name != "" || pass != "" {
		res.Meta["auth_user"] = safe.SanitizeForLog(name)
		res.Meta["auth_pass"] = safe.SanitizeForLog(pass)
		flagAnomaly(res, "couchdb-credential-attempt")
		flagDefaultCred(res, name, pass)
		res.Meta["intent"] = "CouchDB login — _session credential attempt (" + safe.SanitizeForLog(name) + ")"
	}
}

// couchSessionCreds pulls name/password from a form body (name=…&password=…) or
// a JSON body ({"name":"…","password":"…"}).
func couchSessionCreds(s string) (name, pass string) {
	if strings.Contains(s, "name=") || strings.Contains(s, "password=") {
		for _, kv := range strings.Split(s, "&") {
			if v, ok := strings.CutPrefix(kv, "name="); ok {
				name = v
			} else if v, ok := strings.CutPrefix(kv, "password="); ok {
				pass = v
			}
		}
		return
	}
	return jsonStrField(s, "name"), jsonStrField(s, "password")
}

// jsonStrField does a minimal "key":"value" extraction (no full JSON parse).
func jsonStrField(s, key string) string {
	i := strings.Index(s, `"`+key+`"`)
	if i < 0 {
		return ""
	}
	rest := s[i+len(key)+2:]
	c := strings.IndexByte(rest, ':')
	if c < 0 {
		return ""
	}
	rest = strings.TrimSpace(rest[c+1:])
	if len(rest) == 0 || rest[0] != '"' {
		return ""
	}
	rest = rest[1:]
	if e := strings.IndexByte(rest, '"'); e >= 0 {
		return rest[:e]
	}
	return ""
}

func couchDBName(path string) string {
	return safe.SanitizeForLog(strings.Trim(strings.SplitN(strings.TrimPrefix(path, "/"), "/", 2)[0], " "))
}
