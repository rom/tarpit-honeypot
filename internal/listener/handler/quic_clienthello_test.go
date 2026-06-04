package handler

import (
	"context"
	"net"
	"testing"

	"github.com/rom/tarpit-honeypot/internal/config"
)

// richTLSClientHello builds a ClientHello with SNI, ALPN (h3 + http/1.1) and a
// quic_transport_parameters extension, so the deep parser has something to find.
func richTLSClientHello(sni string, alpn []string) []byte {
	body := []byte{0x03, 0x03}
	body = append(body, make([]byte, 32)...)    // random
	body = append(body, 0x00)                   // session_id len
	body = append(body, 0x00, 0x02, 0x13, 0x01) // 1 cipher suite
	body = append(body, 0x01, 0x00)             // compression null

	var ext []byte
	// server_name (0x0000): list_len(2) + entry{ type(1)=0, name_len(2), name }
	name := []byte(sni)
	sniData := []byte{byte((len(name) + 3) >> 8), byte(len(name) + 3),
		0x00, byte(len(name) >> 8), byte(len(name))}
	sniData = append(sniData, name...)
	ext = append(ext, 0x00, 0x00, byte(len(sniData)>>8), byte(len(sniData)))
	ext = append(ext, sniData...)
	// ALPN (0x0010)
	var protos []byte
	for _, a := range alpn {
		protos = append(protos, byte(len(a)))
		protos = append(protos, []byte(a)...)
	}
	alpnData := append([]byte{byte(len(protos) >> 8), byte(len(protos))}, protos...)
	ext = append(ext, 0x00, 0x10, byte(len(alpnData)>>8), byte(len(alpnData)))
	ext = append(ext, alpnData...)
	// quic_transport_parameters (0x0039): two params (id 0x01 len1, id 0x04 len1)
	tp := []byte{0x01, 0x01, 0x1e, 0x04, 0x01, 0x0a}
	ext = append(ext, 0x00, 0x39, byte(len(tp)>>8), byte(len(tp)))
	ext = append(ext, tp...)

	body = append(body, byte(len(ext)>>8), byte(len(ext)))
	body = append(body, ext...)
	hs := []byte{0x01, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	return append(hs, body...)
}

func TestParseQUICClientHello(t *testing.T) {
	ch := richTLSClientHello("api.victim.example", []string{"h3", "http/1.1"})
	info := parseQUICClientHello(ch)
	if info.SNI != "api.victim.example" {
		t.Errorf("SNI = %q", info.SNI)
	}
	if len(info.ALPN) != 2 || info.ALPN[0] != "h3" {
		t.Errorf("ALPN = %v", info.ALPN)
	}
	if !info.HTTP3 {
		t.Error("HTTP3 should be detected from h3 ALPN")
	}
	if len(info.TransportParam) != 2 || info.TransportParam[0] != 0x01 {
		t.Errorf("transport params = %v", info.TransportParam)
	}
}

func TestParseQUICClientHelloH3Draft(t *testing.T) {
	info := parseQUICClientHello(richTLSClientHello("h.example", []string{"h3-29"}))
	if !info.HTTP3 {
		t.Error("h3-29 draft ALPN should count as HTTP/3")
	}
}

func TestParseQUICClientHelloNoH3(t *testing.T) {
	info := parseQUICClientHello(richTLSClientHello("h.example", []string{"doq"}))
	if info.HTTP3 {
		t.Error("doq ALPN is not HTTP/3")
	}
	if info.SNI != "h.example" {
		t.Errorf("SNI = %q", info.SNI)
	}
}

func TestParseQUICClientHelloMalformed(t *testing.T) {
	for _, b := range [][]byte{nil, {0x01}, {0x02, 0, 0, 0}, make([]byte, 40)} {
		_ = parseQUICClientHello(b) // must not panic
	}
}

// End-to-end: a QUIC Initial carrying an h3 ClientHello must surface SNI,
// ALPN and the http3 flag through the handler.
func TestQUICHandlerExtractsHTTP3(t *testing.T) {
	dcid := []byte{0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08}
	ch := richTLSClientHello("edge.target.example", []string{"h3"})
	pkt := buildQUICInitial(t, dcid, ch)

	res, _ := (&quicH{}).Handle(context.Background(), pkt, &net.UDPAddr{}, nil, config.Listener{})
	if res.Meta["quic_sni"] != "edge.target.example" {
		t.Errorf("quic_sni = %v", res.Meta["quic_sni"])
	}
	if res.Meta["http3"] != true {
		t.Errorf("http3 flag not set; meta=%v", res.Meta)
	}
	if !hasAnom(res, "quic-http3") {
		t.Errorf("quic-http3 anomaly not flagged; meta=%v", res.Meta["anomalies"])
	}
	alpn, _ := res.Meta["quic_alpn"].([]string)
	if len(alpn) == 0 || alpn[0] != "h3" {
		t.Errorf("quic_alpn = %v", res.Meta["quic_alpn"])
	}
}
