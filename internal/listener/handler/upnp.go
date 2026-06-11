package handler

import (
	"context"
	"net"
	"strings"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/cve"
	"github.com/rom/tarpit-honeypot/internal/identity"
	"github.com/rom/tarpit-honeypot/internal/safe"
	"github.com/rom/tarpit-honeypot/internal/toolfp"
)

// upnp emulates the HTTP control plane of a UPnP IGD (Internet Gateway Device)
// — the endpoints a consumer router exposes once SSDP discovery (the ssdp
// handler, UDP 1900) has pointed a client at its LOCATION URL: the device
// description (rootDesc.xml), the SOAP control URLs for WANIPConnection /
// WANPPPConnection, and GENA eventing (SUBSCRIBE). These are the surfaces
// behind the headline UPnP attacks:
//
//   - UPnProxy: AddPortMapping injecting NAT entries that turn the device into
//     an open proxy / relay (CWE-441).
//   - CallStranger (CVE-2020-12695): a SUBSCRIBE Callback to an attacker URL
//     for SSRF, data exfiltration, and reflected DDoS (CWE-918).
//   - SOAP command injection on OEM stacks: Realtek miniigd NewInternalClient
//     (CVE-2014-8361) and Huawei HG532 DeviceUpgrade NewStatusURL
//     (CVE-2017-17215).
//
// We serve a believable IGD: a device-description XML on a description GET, a
// plausible SOAP action response on control POSTs (e.g. a fake external IP),
// and a GENA 200 on SUBSCRIBE. Nothing is executed or actually proxied —
// the handler recognizes the abuse, attributes CVE/CWE + ATT&CK, sets intent,
// and harvests the action + injected payload.
type upnp struct{ id *identity.Identity }

func (u *upnp) Name() string { return "upnp" }

func (u *upnp) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	withTimeout(conn, cfg.ReadTimeout)
	res := Result{Meta: map[string]any{}}
	h, ok := readCPEHTTP(conn, cfg)
	if !ok {
		res.Meta["read_err"] = "no request"
		return res, nil
	}
	res.Payload = h.Raw
	raw := string(h.Raw)
	low := strings.ToLower(raw)
	res.Meta["request_line"] = safe.SanitizeForLog(strings.TrimSpace(h.Method + " " + h.URI + " " + h.Proto))
	res.Meta["protocol_name"] = "UPnP IGD"
	if h.Method != "" {
		res.Meta["http_method"] = h.Method
	}
	if h.URI != "" {
		res.Meta["http_uri"] = safe.SanitizeForLog(clipStr(h.URI, 512))
	}
	if ua := h.header("user-agent"); ua != "" {
		res.Meta["user_agent"] = safe.SanitizeForLog(clipStr(ua, 256))
	}

	// --- Fingerprint: the SOAP action (service URN + action), and the tool. ---
	svcURN, action := soapAction(h)
	if action != "" {
		res.Meta["soap_action"] = safe.SanitizeForLog(clipStr(action, 128))
	}
	if svcURN != "" {
		res.Meta["soap_service"] = safe.SanitizeForLog(clipStr(svcURN, 160))
	}
	if v := toolfp.IdentifyHTTP(toolfp.HTTPSignals{
		Method: h.Method, Path: h.URI, UserAgent: h.header("user-agent"), HeaderKeys: headerKeys(h),
	}); len(v.Tools) > 0 {
		res.Meta["tools"] = v.Tools
		res.Meta["tool_confidence"] = v.Confidence
		if v.Automation {
			res.Meta["automation"] = true
		}
	}

	// --- CVE exploit-attempt recognition (UPnP-specific + generic HTTP). ---
	for _, svc := range []string{"upnp", "http"} {
		for _, rec := range cve.MatchPayload(svc, raw) {
			res.CVEHits = appendUnique(res.CVEHits, rec.ID)
			flagAnomaly(&res, "cve:"+rec.ID)
		}
	}

	intent := "UPnP IGD probe — device enumeration"
	method := strings.ToUpper(h.Method)

	switch {
	// GENA SUBSCRIBE with a Callback to an off-device URL = CallStranger.
	case method == "SUBSCRIBE":
		cb := h.header("callback")
		res.Meta["gena_callback"] = safe.SanitizeForLog(clipStr(cb, 256))
		flagAnomaly(&res, "upnp-gena-subscribe")
		if callstrangerCallback(cb) {
			flagAnomaly(&res, "upnp-callstranger")
			res.CVEHits = appendUnique(res.CVEHits, "CVE-2020-12695")
			flagAnomaly(&res, "cve:CVE-2020-12695")
			noteCWE(&res, "CWE-918") // server-side request forgery
			intent = "UPnP CallStranger — SUBSCRIBE Callback to an external URL (SSRF / exfiltration / reflected DDoS, CVE-2020-12695)"
		} else {
			intent = "UPnP GENA SUBSCRIBE — event subscription"
		}

	// SOAP control action.
	case action != "" || strings.Contains(low, "soap") || method == "POST":
		switch {
		// Realtek miniigd (picsdesc.xml) + Huawei HG532 (DeviceUpgrade /
		// NewStatusURL) OEM stacks, or any SOAP argument carrying shell
		// metacharacters. NewInternalClient on its own is a *normal* AddPort-
		// Mapping argument, so it only counts when paired with an injection.
		case containsAny(low, "picsdesc.xml", "newstatusurl", "newdownloadurl", "deviceupgrade") ||
			(strings.Contains(low, "newinternalclient") && shellMetacharacters(low)):
			flagAnomaly(&res, "upnp-command-injection")
			noteCWE(&res, "CWE-78") // OS command injection (Realtek / Huawei OEM stacks)
			intent = "UPnP SOAP command injection (NewInternalClient / DeviceUpgrade) — RCE on the router (Mirai/Satori-class)"
		case actionIs(action, "AddPortMapping") || strings.Contains(low, "addportmapping"):
			flagAnomaly(&res, "upnp-addportmapping")
			noteCWE(&res, "CWE-441") // unintended proxy / intermediary (UPnProxy)
			res.Meta["upnp_port_mapping"] = portMappingSummary(string(h.Body))
			intent = "UPnP AddPortMapping — injecting a NAT port-forward (UPnProxy: turning the device into an open relay)"
		case actionIs(action, "GetGenericPortMappingEntry") || actionIs(action, "GetSpecificPortMappingEntry") || strings.Contains(low, "portmappingentry"):
			flagAnomaly(&res, "upnp-portmap-enum")
			intent = "UPnP port-mapping enumeration — reading the device's NAT table"
		case actionIs(action, "GetExternalIPAddress") || strings.Contains(low, "getexternalipaddress"):
			flagAnomaly(&res, "upnp-control-probe")
			intent = "UPnP GetExternalIPAddress — IGD control-endpoint probe"
		default:
			flagAnomaly(&res, "upnp-control-probe")
			intent = "UPnP SOAP control action — IGD manipulation"
		}

	// Device description fetch (rootDesc.xml / description.xml / igd.xml / scpd).
	case method == "GET" || method == "HEAD":
		flagAnomaly(&res, "upnp-device-description")
		intent = "UPnP device-description fetch — IGD service/capability enumeration"
	}
	setIfEmpty(res.Meta, "intent", intent)

	u.respond(conn, &res, h, action)
	return res, nil
}

// respond writes the believable IGD reply for the request shape.
func (u *upnp) respond(conn net.Conn, res *Result, h httpHead, action string) {
	server := "Linux/2.6.36 UPnP/1.0 MiniUPnPd/1.9"
	method := strings.ToUpper(h.Method)
	switch {
	case method == "SUBSCRIBE":
		resp := cpeHTTPResp("200 OK", server, "", "",
			`SID: uuid:`+upnpUUID(u.id),
			`TIMEOUT: Second-1800`)
		writeConn(conn, res, resp)
		res.BannerSent = "upnp GENA 200"
	case method == "POST" || action != "":
		body := upnpSOAPResponse(action)
		resp := cpeHTTPResp("200 OK", server, `text/xml; charset="utf-8"`, body, `EXT:`)
		writeConn(conn, res, resp)
		res.BannerSent = "upnp SOAP response"
	case method == "GET" || method == "HEAD" || method == "":
		body := upnpRootDesc(u.id)
		resp := cpeHTTPResp("200 OK", server, `text/xml; charset="utf-8"`, body)
		writeConn(conn, res, resp)
		res.BannerSent = "upnp rootDesc.xml"
	default:
		writeConn(conn, res, cpeHTTPResp("405 Method Not Allowed", server, "", ""))
		res.BannerSent = "upnp"
	}
}

// callstrangerCallback reports whether a GENA Callback header points at an
// off-device http(s) URL (the CallStranger SSRF/exfil precondition). Callbacks
// are wrapped in angle brackets: "<http://attacker/cb>".
func callstrangerCallback(cb string) bool {
	low := strings.ToLower(cb)
	if !strings.Contains(low, "http://") && !strings.Contains(low, "https://") {
		return false
	}
	// A loopback/empty callback is benign-shaped; anything else is the abuse.
	if strings.Contains(low, "127.0.0.1") || strings.Contains(low, "localhost") {
		return false
	}
	return true
}

// portMappingSummary scavenges the salient AddPortMapping arguments (external
// port, internal client+port, protocol) for the event meta.
func portMappingSummary(body string) string {
	parts := []string{}
	for _, tag := range []string{"NewProtocol", "NewExternalPort", "NewInternalClient", "NewInternalPort"} {
		if v := xmlElem(body, tag); v != "" {
			parts = append(parts, tag[3:]+"="+safe.SanitizeForLog(clipStr(v, 48)))
		}
	}
	return strings.Join(parts, " ")
}

func upnpSOAPResponse(action string) string {
	switch {
	case actionIs(action, "GetExternalIPAddress"):
		return soapEnvelope(`<u:GetExternalIPAddressResponse xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">` +
			`<NewExternalIPAddress>203.0.113.42</NewExternalIPAddress></u:GetExternalIPAddressResponse>`)
	case actionIs(action, "AddPortMapping"):
		return soapEnvelope(`<u:AddPortMappingResponse xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1"/>`)
	case actionIs(action, "GetGenericPortMappingEntry"), actionIs(action, "GetSpecificPortMappingEntry"):
		return soapEnvelope(`<u:GetGenericPortMappingEntryResponse xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">` +
			`<NewRemoteHost></NewRemoteHost><NewExternalPort>0</NewExternalPort><NewProtocol>TCP</NewProtocol>` +
			`<NewInternalPort>0</NewInternalPort><NewInternalClient>192.168.1.2</NewInternalClient>` +
			`<NewEnabled>1</NewEnabled><NewPortMappingDescription>decoy</NewPortMappingDescription>` +
			`<NewLeaseDuration>0</NewLeaseDuration></u:GetGenericPortMappingEntryResponse>`)
	}
	// Generic SOAP fault for unknown actions — believable, action-agnostic.
	return soapEnvelope(`<s:Fault><faultcode>s:Client</faultcode><faultstring>UPnPError</faultstring>` +
		`<detail><UPnPError xmlns="urn:schemas-upnp-org:control-1-0"><errorCode>401</errorCode>` +
		`<errorDescription>Invalid Action</errorDescription></UPnPError></detail></s:Fault>`)
}

func soapEnvelope(inner string) string {
	return `<?xml version="1.0"?>` +
		`<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" ` +
		`s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body>` + inner + `</s:Body></s:Envelope>`
}

// upnpRootDesc is the decoy IGD device description.
func upnpRootDesc(id *identity.Identity) string {
	uuid := upnpUUID(id)
	return `<?xml version="1.0"?>` +
		`<root xmlns="urn:schemas-upnp-org:device-1-0"><specVersion><major>1</major><minor>0</minor></specVersion>` +
		`<device><deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType>` +
		`<friendlyName>WAN Router</friendlyName><manufacturer>D-Link</manufacturer>` +
		`<modelName>DIR-850L</modelName><modelNumber>1.0</modelNumber>` +
		`<UDN>uuid:` + uuid + `</UDN>` +
		`<serviceList><service><serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>` +
		`<serviceId>urn:upnp-org:serviceId:WANIPConn1</serviceId>` +
		`<controlURL>/ctl/IPConn</controlURL><eventSubURL>/evt/IPConn</eventSubURL>` +
		`<SCPDURL>/WANIPCn.xml</SCPDURL></service></serviceList></device></root>`
}

func upnpUUID(id *identity.Identity) string {
	if id == nil {
		return "11223344-5566-7788-99aa-bbccddeeff00"
	}
	a := itoa32hex(id.Uint32("upnp/uuid"))
	b := itoa32hex(id.Uint32("upnp/uuid2"))
	return a[:8] + "-" + a[:4] + "-" + b[:4] + "-" + b[4:8] + "-" + a + b[:4]
}

// actionIs compares a SOAP action local-name case-insensitively.
func actionIs(action, want string) bool { return strings.EqualFold(action, want) }

// containsAny reports whether s contains any of subs (s expected lower-cased).
func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}
