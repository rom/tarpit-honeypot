package handler

import (
	"encoding/binary"
	"strings"
)

// Deep parse of the TLS ClientHello recovered from a QUIC Initial packet.
//
// The QUIC handler already decrypts the Initial flight (RFC 9001 keys derived
// from the public salt + client DCID) and reassembles the ClientHello. This
// extracts the request-shaping fields from it: the SNI host the client asked
// for, the offered ALPN list (which reveals HTTP/3 — "h3" — vs other QUIC
// protocols), and the QUIC transport-parameter IDs the client advertised.
//
// This is the most that is recoverable without completing the handshake: the
// actual HTTP/3 request (the :method / :path, sent as 1-RTT application data)
// is encrypted under keys derived from the (EC)DHE handshake, which would
// require standing up a full QUIC+TLS 1.3 server. That remains out of scope
// (the sensor is a decoy stack, never a real upstream) — see docs/design.md.

// quicHelloInfo is the parsed, human-meaningful content of a QUIC ClientHello.
type quicHelloInfo struct {
	SNI            string
	ALPN           []string
	HTTP3          bool
	TransportParam []uint64 // advertised QUIC transport-parameter IDs
}

// parseQUICClientHello parses a TLS Handshake ClientHello message (type 0x01 +
// 3-byte length + body) and returns its SNI / ALPN / transport-parameter info.
// Best-effort: a truncated or malformed message yields whatever parsed.
func parseQUICClientHello(hs []byte) quicHelloInfo {
	var info quicHelloInfo
	if len(hs) < 4 || hs[0] != 0x01 {
		return info
	}
	// handshake length (3 bytes), then ClientHello body.
	body := hs[4:]
	p := 0
	// legacy_version(2) + random(32).
	if len(body) < p+34 {
		return info
	}
	p += 34
	// session_id: len(1) + id.
	if len(body) < p+1 {
		return info
	}
	sidLen := int(body[p])
	p += 1 + sidLen
	// cipher_suites: len(2) + suites.
	if len(body) < p+2 {
		return info
	}
	csLen := int(binary.BigEndian.Uint16(body[p:]))
	p += 2 + csLen
	// compression_methods: len(1) + methods.
	if len(body) < p+1 {
		return info
	}
	cmLen := int(body[p])
	p += 1 + cmLen
	// extensions: len(2) + extensions.
	if len(body) < p+2 {
		return info
	}
	extTotal := int(binary.BigEndian.Uint16(body[p:]))
	p += 2
	if p+extTotal > len(body) {
		extTotal = len(body) - p
	}
	ext := body[p : p+extTotal]

	for q := 0; q+4 <= len(ext); {
		etype := binary.BigEndian.Uint16(ext[q:])
		elen := int(binary.BigEndian.Uint16(ext[q+2:]))
		q += 4
		if q+elen > len(ext) {
			break
		}
		edata := ext[q : q+elen]
		q += elen
		switch etype {
		case 0x0000: // server_name
			info.SNI = parseSNI(edata)
		case 0x0010: // application_layer_protocol_negotiation
			info.ALPN = parseALPN(edata)
		case 0x0039, 0xffa5: // quic_transport_parameters (RFC 9001 / draft codepoint)
			info.TransportParam = parseTransportParamIDs(edata)
		}
	}
	for _, a := range info.ALPN {
		if a == "h3" || strings.HasPrefix(a, "h3-") {
			info.HTTP3 = true
		}
	}
	return info
}

// parseSNI extracts the first host_name from a server_name extension.
func parseSNI(d []byte) string {
	// server_name_list: list_len(2), entries: type(1) + name_len(2) + name.
	if len(d) < 2 {
		return ""
	}
	listLen := int(binary.BigEndian.Uint16(d))
	if 2+listLen > len(d) {
		return ""
	}
	l := d[2 : 2+listLen]
	if len(l) < 3 || l[0] != 0x00 { // host_name type
		return ""
	}
	nameLen := int(binary.BigEndian.Uint16(l[1:]))
	if 3+nameLen > len(l) {
		return ""
	}
	return string(l[3 : 3+nameLen])
}

// parseALPN extracts the protocol-name list from an ALPN extension.
func parseALPN(d []byte) []string {
	if len(d) < 2 {
		return nil
	}
	listLen := int(binary.BigEndian.Uint16(d))
	if 2+listLen > len(d) {
		return nil
	}
	l := d[2 : 2+listLen]
	var out []string
	for i := 0; i < len(l); {
		n := int(l[i])
		i++
		if i+n > len(l) {
			break
		}
		out = append(out, string(l[i:i+n]))
		i += n
		if len(out) >= 16 {
			break
		}
	}
	return out
}

// parseTransportParamIDs returns the advertised QUIC transport-parameter IDs
// (each is a varint id + varint length + value). IDs alone are good intel:
// they reveal the client's QUIC stack/version posture.
func parseTransportParamIDs(d []byte) []uint64 {
	var ids []uint64
	for i := 0; i < len(d); {
		id, n := quicVarint(d[i:])
		if n == 0 {
			break
		}
		i += n
		vlen, n2 := quicVarint(d[i:])
		if n2 == 0 {
			break
		}
		i += n2 + int(vlen)
		if i > len(d) {
			break
		}
		ids = append(ids, id)
		if len(ids) >= 32 {
			break
		}
	}
	return ids
}
