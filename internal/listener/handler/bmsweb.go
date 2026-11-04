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

// bmsWeb emulates the web management interface of commercial
// refrigeration / building-management controllers beyond Danfoss AK-SM —
// the vendors whose supermarket, cold-storage and HVAC controllers end up
// internet-exposed. It fingerprints each product, captures the login
// (including the well-known default credentials), and flags the
// refrigeration/BMS actuation and known-weakness probes. Capture + fingerprint
// only; nothing is actuated.
//
//	dixell   Emerson/Copeland Dixell XWEB  (supermarket refrigeration supervisor)
//	carel    CAREL pCOWeb / boss building-controller web
//	trane    Trane Tracer SC / Concierge BAS supervisor
//	resideo  Resideo/Honeywell building controller web
type bmsWeb struct{ kind string }

func (h *bmsWeb) Name() string { return h.kind }

type bmsPersona struct {
	server  string
	title   string
	product string
	defUser string
	defPass string
}

func bmsPersonaFor(kind string) bmsPersona {
	switch kind {
	case "dixell":
		return bmsPersona{server: "Boa/0.94.13", title: "XWEB500", product: "Emerson/Copeland Dixell XWEB500EVO", defUser: "admin", defPass: "dixell"}
	case "carel":
		return bmsPersona{server: "pCOWeb", title: "CAREL pCOWeb", product: "CAREL pCOWeb / boss", defUser: "admin", defPass: "fadmin"}
	case "trane":
		return bmsPersona{server: "Tracer SC", title: "Tracer SC", product: "Trane Tracer SC+ / Concierge", defUser: "admin", defPass: "trane"}
	case "resideo":
		return bmsPersona{server: "lighttpd", title: "Resideo", product: "Resideo/Honeywell building controller", defUser: "administrator", defPass: "admin"}
	}
	return bmsPersona{server: "Server", title: "BMS", product: "building controller", defUser: "admin", defPass: "admin"}
}

func (h *bmsWeb) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	withTimeout(conn, cfg.ReadTimeout)
	res := Result{Meta: map[string]any{}}
	p := bmsPersonaFor(h.kind)
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
	res.Meta["product"] = p.product
	if ua != "" {
		res.Meta["user_agent"] = safe.SanitizeForLog(ua)
	}
	flagAnomaly(&res, h.kind+"-probe")
	flagAnomaly(&res, "bms-web-probe")

	// Credentials: Basic auth or a posted login form.
	if u, pw, ok := decodeBasic(authz); ok {
		res.Meta["basic_user"] = safe.SanitizeForLog(u)
		res.Meta["basic_pass"] = safe.SanitizeForLog(pw)
		h.flagCreds(&res, u, pw, p)
	}
	var body []byte
	if method == "POST" || method == "PUT" {
		body = svcHTTPBody(br, head, capN)
		res.Payload = append(res.Payload, body...)
		if u, pw := parseLoginForm(body); u != "" || pw != "" {
			res.Meta["form_user"] = safe.SanitizeForLog(u)
			res.Meta["form_pass"] = safe.SanitizeForLog(pw)
			h.flagCreds(&res, u, pw, p)
		}
	}

	// Refrigeration/BMS actuation intent: setpoint / defrost / alarm / schedule
	// writes over the web interface (mirrors the OT behaviour model).
	hay := strings.ToLower(path + "?" + query + "\n" + string(body))
	if containsAnyFold(hay, "setpoint", "set_point", "defrost", "setcfg", "writeparam", "write_param", "/set?", "alarmcfg") {
		flagAnomaly(&res, "refrigeration-setpoint-write")
		setIfEmpty(res.Meta, "intent", p.product+" parameter/setpoint/defrost write over the web interface")
	}
	// Path traversal through the embedded web server (classic on these small
	// appliance HTTPds).
	dec := hay
	if strings.Contains(dec, "../") || strings.Contains(dec, "..%2f") || strings.Contains(dec, "..\\") {
		flagAnomaly(&res, "bms-web-traversal")
		setIfEmpty(res.Meta, "intent", p.product+" web-server path traversal")
	}

	// Shared HTTP CVE corpus (traversal / SSRF / log4shell probes land here too).
	for _, rec := range cve.MatchPayload("http", string(res.Payload)) {
		res.CVEHits = appendUnique(res.CVEHits, rec.ID)
		flagAnomaly(&res, "cve:"+rec.ID)
	}

	body2 := "<html><head><title>" + p.title + "</title></head><body><h1>" + p.title +
		"</h1><form method=\"post\" action=\"/login\"><input name=\"username\"><input type=\"password\" name=\"password\">" +
		"<input type=\"submit\" value=\"Login\"></form></body></html>"
	extra := "Server: " + safe.SanitizeHeader(p.server) + "\r\n"
	if _, err := conn.Write([]byte(svcHTTPResp("200 OK", extra, "text/html; charset=UTF-8", body2))); err != nil {
		res.Meta["write_err"] = err.Error()
	}
	res.BannerSent = h.kind + " bms web"
	return res, nil
}

func (h *bmsWeb) flagCreds(res *Result, user, pass string, p bmsPersona) {
	flagAnomaly(res, h.kind+"-login-attempt")
	flagDefaultCred(res, user, pass)
	if strings.EqualFold(user, p.defUser) && pass == p.defPass {
		flagAnomaly(res, "bms-default-cred")
		res.Meta["intent"] = p.product + " login with the vendor default credentials"
	}
}

// containsAnyFold reports whether low (already lower-cased) contains any of subs.
func containsAnyFold(low string, subs ...string) bool {
	for _, s := range subs {
		if strings.Contains(low, s) {
			return true
		}
	}
	return false
}
