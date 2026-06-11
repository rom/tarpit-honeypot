package handler

import (
	"context"
	"net"
	"regexp"
	"strings"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/cve"
	"github.com/rom/tarpit-honeypot/internal/identity"
	"github.com/rom/tarpit-honeypot/internal/safe"
	"github.com/rom/tarpit-honeypot/internal/toolfp"
)

// tr069 emulates the CPE side of the CPE WAN Management Protocol (TR-069 /
// CWMP) — the HTTP/SOAP "connection request" service a broadband CPE exposes,
// classically on TCP 7547, so its Auto-Configuration Server (ACS) can poke it
// to call home. Port 7547 is one of the most attacked ports on the internet:
// the embedded RomPager / "Misfortune Cookie" HTTP stack (CVE-2014-9222) and
// the TR-064 SetNTPServers command injection reachable on it (CVE-2016-10372)
// drove the November-2016 Deutsche Telekom / Mirai outage.
//
// We present a believable RomPager-fronted CWMP CPE: a Digest 401 on a bare
// GET (the connection-request endpoint is auth-protected) and a CWMP SOAP
// InformResponse on a POSTed envelope. Nothing is executed — we recognize the
// exploit shapes (command injection in NewNTPServer / NewStatusURL / the
// Download RPC, the Misfortune Cookie, TR-064 actions), attribute the CVE/CWE
// and ATT&CK, set the attacker's intent, and harvest the SOAP method, the ACS /
// device identity, and any injected payload.
type tr069 struct{ id *identity.Identity }

func (t *tr069) Name() string { return "tr069" }

// misfortuneCookieRe matches the RomPager Misfortune Cookie marker: a cookie
// named C<index>=<value> whose numeric index selects an internal allocation
// slot to corrupt (CVE-2014-9222). The PoC indices vary, so we match the shape
// rather than one constant.
var misfortuneCookieRe = regexp.MustCompile(`(?i)\bC\d{5,7}=`)

// cwmpMethods are the CWMP RPC method local-names we recognize in a SOAP body.
var cwmpMethods = []string{
	"Inform", "GetParameterValues", "SetParameterValues", "GetParameterNames",
	"SetParameterAttributes", "GetParameterAttributes", "AddObject", "DeleteObject",
	"Download", "Upload", "ScheduleDownload", "Reboot", "FactoryReset",
	"GetRPCMethods", "TransferComplete", "ChangeDUState",
}

// tr064CmdInjectActions are the TR-064 SOAP actions (reachable on the TR-069
// port on Eir/Zyxel/Speedport CPEs) whose parameters were the Mirai command-
// injection vector.
var tr064CmdInjectActions = []string{"setntpservers", "newntpserver", "newstatusurl", "newdownloadurl"}

func (t *tr069) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	withTimeout(conn, cfg.ReadTimeout)
	res := Result{Meta: map[string]any{}}
	h, ok := readCPEHTTP(conn, cfg)
	if !ok {
		res.Meta["read_err"] = "no request"
		return res, nil
	}
	res.Payload = h.Raw
	res.Meta["request_line"] = safe.SanitizeForLog(strings.TrimSpace(h.Method + " " + h.URI + " " + h.Proto))
	res.Meta["protocol_name"] = "TR-069 CWMP"
	if h.Method != "" {
		res.Meta["http_method"] = h.Method
	}
	if h.URI != "" {
		res.Meta["http_uri"] = safe.SanitizeForLog(clipStr(h.URI, 512))
	}
	if ua := h.header("user-agent"); ua != "" {
		res.Meta["user_agent"] = safe.SanitizeForLog(clipStr(ua, 256))
	}

	body := string(h.Body)
	raw := string(h.Raw)
	low := strings.ToLower(raw)

	// --- Fingerprint: SOAP action + CWMP method + the ACS/device identity the
	// peer presents (so a scanner's CWMP shape and any spoofed CPE identity are
	// recorded). ---
	if svc, action := soapAction(h); action != "" {
		res.Meta["soap_action"] = safe.SanitizeForLog(clipStr(action, 128))
		if svc != "" {
			res.Meta["soap_service"] = safe.SanitizeForLog(clipStr(svc, 160))
		}
	}
	method := cwmpMethodOf(body)
	if method != "" {
		res.Meta["cwmp_method"] = method
	}
	captureCWMPIdentity(&res, body)

	// Tool / scanner fingerprint from the HTTP signals.
	if v := toolfp.IdentifyHTTP(toolfp.HTTPSignals{
		Method: h.Method, Path: h.URI, UserAgent: h.header("user-agent"), HeaderKeys: headerKeys(h),
	}); len(v.Tools) > 0 {
		res.Meta["tools"] = v.Tools
		res.Meta["tool_confidence"] = v.Confidence
		if v.Automation {
			res.Meta["automation"] = true
		}
	}

	// --- CVE exploit-attempt recognition (TR-069/TR-064 + the generic HTTP
	// layer). Detection only. ---
	for _, svc := range []string{"tr069", "http"} {
		for _, rec := range cve.MatchPayload(svc, raw) {
			res.CVEHits = appendUnique(res.CVEHits, rec.ID)
			flagAnomaly(&res, "cve:"+rec.ID)
		}
	}

	// --- Misuse / manipulation recognition + intent + CWE attribution. ---
	intent := "TR-069 CWMP connection-request probe — ACS impersonation / unmanaged-CPE takeover attempt"

	// Misfortune Cookie (RomPager memory corruption via crafted Cookie).
	if c := h.header("cookie"); c != "" && misfortuneCookieRe.MatchString(c) {
		flagAnomaly(&res, "tr069-misfortune-cookie")
		res.CVEHits = appendUnique(res.CVEHits, "CVE-2014-9222")
		flagAnomaly(&res, "cve:CVE-2014-9222")
		noteCWE(&res, "CWE-787") // out-of-bounds write
		intent = "TR-069 Misfortune Cookie — RomPager memory corruption / device takeover (CVE-2014-9222)"
	}

	// TR-064 command injection (NewNTPServer / SetNTPServers / NewStatusURL …).
	if injectedTR064(low) {
		flagAnomaly(&res, "tr069-command-injection")
		noteCWE(&res, "CWE-78") // OS command injection
		intent = "TR-069/TR-064 command injection via " + injectedParam(low) + " — remote code execution on the CPE (Mirai-class)"
	} else if method != "" {
		switch method {
		case "Download", "ScheduleDownload", "ChangeDUState", "Upload":
			flagAnomaly(&res, "tr069-firmware-push")
			noteCWE(&res, "CWE-494") // download of code without integrity check
			intent = "TR-069 " + method + " RPC — pushing firmware / config to the CPE (persistence / tampering)"
		case "FactoryReset", "Reboot":
			flagAnomaly(&res, "tr069-disruptive-rpc")
			noteCWE(&res, "CWE-306")
			intent = "TR-069 " + method + " RPC — disruptive control of the CPE"
		case "SetParameterValues", "AddObject", "SetParameterAttributes":
			flagAnomaly(&res, "tr069-parameter-write")
			intent = "TR-069 " + method + " — writing CPE configuration parameters (control manipulation)"
		default:
			flagAnomaly(&res, "tr069-soap-probe")
			intent = "TR-069 CWMP " + method + " — ACS-style management of the CPE"
		}
	} else {
		// A bare GET to the connection-request URL with no SOAP body is the
		// classic 7547 mass-scan / connection-request trigger.
		flagAnomaly(&res, "tr069-connection-request")
		noteCWE(&res, "CWE-306") // missing authentication for the management surface
	}
	setIfEmpty(res.Meta, "intent", intent)

	// --- Decoy response. ---
	t.respond(conn, &res, h, method)
	return res, nil
}

// respond writes the believable CPE reply: a Digest 401 to an unauthenticated
// bare GET (the connection-request endpoint is auth-protected), or a CWMP SOAP
// InformResponse to a posted envelope.
func (t *tr069) respond(conn net.Conn, res *Result, h httpHead, method string) {
	server := "RomPager/4.07 UPnP/1.0"
	switch {
	case h.Method == "POST" && (method != "" || strings.Contains(strings.ToLower(string(h.Body)), "soap")):
		body := cwmpInformResponse()
		resp := cpeHTTPResp("200 OK", server, `text/xml; charset="utf-8"`, body,
			`SOAPServer: cwmp/1.0`)
		writeConn(conn, res, resp)
		res.BannerSent = "tr069 cwmp InformResponse"
	case h.Method == "GET" || h.Method == "HEAD" || h.Method == "":
		realm := "RomPager"
		nonce := romNonce(t.id)
		resp := cpeHTTPResp("401 Unauthorized", server, "text/html", romUnauthBody(),
			`WWW-Authenticate: Digest realm="`+realm+`", qop="auth", nonce="`+nonce+`", stale=false`)
		writeConn(conn, res, resp)
		res.BannerSent = "tr069 RomPager 401"
	default:
		resp := cpeHTTPResp("204 No Content", server, "", "")
		writeConn(conn, res, resp)
		res.BannerSent = "tr069 cwmp"
	}
}

// cwmpMethodOf returns the CWMP RPC method local-name found in a SOAP body, or "".
func cwmpMethodOf(body string) string {
	for _, m := range cwmpMethods {
		if strings.Contains(body, "cwmp:"+m) || strings.Contains(body, "<"+m+">") ||
			strings.Contains(body, ":"+m+">") || strings.Contains(body, ":"+m+" ") {
			return m
		}
	}
	return ""
}

// captureCWMPIdentity scavenges the device identity an Inform advertises
// (OUI / ProductClass / SerialNumber / Manufacturer) into meta — what the peer
// claims to be, useful when an attacker spoofs a CPE to an ACS.
func captureCWMPIdentity(res *Result, body string) {
	for tag, key := range map[string]string{
		"OUI": "cwmp_oui", "ProductClass": "cwmp_product_class",
		"SerialNumber": "cwmp_serial", "Manufacturer": "cwmp_manufacturer",
	} {
		if v := xmlElem(body, tag); v != "" {
			res.Meta[key] = safe.SanitizeForLog(clipStr(v, 96))
		}
	}
}

// injectedTR064 reports whether the request carries a TR-064 command-injection
// action with shell metacharacters in its value.
func injectedTR064(low string) bool {
	for _, a := range tr064CmdInjectActions {
		if strings.Contains(low, a) && shellMetacharacters(low) {
			return true
		}
	}
	return false
}

func injectedParam(low string) string {
	for _, a := range tr064CmdInjectActions {
		if strings.Contains(low, a) {
			return a
		}
	}
	return "NewNTPServer"
}

// cwmpInformResponse is the decoy CWMP InformResponse envelope.
func cwmpInformResponse() string {
	return `<?xml version="1.0" encoding="UTF-8"?>` +
		`<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" ` +
		`xmlns:cwmp="urn:dslforum-org:cwmp-1-0">` +
		`<soap:Header><cwmp:ID soap:mustUnderstand="1">1</cwmp:ID></soap:Header>` +
		`<soap:Body><cwmp:InformResponse><MaxEnvelopes>1</MaxEnvelopes></cwmp:InformResponse></soap:Body>` +
		`</soap:Envelope>`
}

func romUnauthBody() string {
	return "<html><head><title>401 Unauthorized</title></head><body>" +
		"<h1>401 Unauthorized</h1><p>RomPager Advanced Version 4.07</p></body></html>"
}

// romNonce derives a stable-per-deployment Digest nonce so the persona is
// consistent across probes from the same scanner.
func romNonce(id *identity.Identity) string {
	if id == nil {
		return "deadbeefcafebabe0123456789abcdef"
	}
	return itoa32hex(id.Uint32("tr069/nonce")) + itoa32hex(id.Uint32("tr069/nonce2"))
}
