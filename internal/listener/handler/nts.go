package handler

import (
	"context"
	crand "crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"

	"github.com/rom/tarpit-honeypot/internal/archetype"
	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/fingerprint"
)

// nts is an NTS-KE (Network Time Security Key Establishment, RFC 8915)
// responder on TCP 4460. NTS-KE runs over TLS with ALPN "ntske/1": the client
// connects, negotiates the next protocol (NTPv4) and an AEAD algorithm, and the
// server returns a set of NTS cookies the client then uses on the NTP/UDP side.
//
// We terminate TLS (capturing JA3/JA4/JA3S + SNI + ALPN — a strong client-stack
// fingerprint), parse the client's NTS-KE record stream (its offered
// next-protocols + AEAD algorithms), and answer with a believable NTS-KE
// response (NTPv4 + AES-SIV-CMAC-256 + a handful of opaque cookies + end-of-
// message). Fingerprint-grade: the cookies are random and never honored on the
// NTP side; nothing is actually keyed.
type nts struct {
	mgr  *certManager
	arch *archetype.Profile
}

func (n *nts) Name() string { return "nts" }

// NTS-KE record types (RFC 8915 §4). The high bit of the type field is the
// "critical" flag.
const (
	ntsRecEndOfMessage = 0
	ntsRecNextProto    = 1
	ntsRecError        = 2
	ntsRecAEAD         = 4
	ntsRecNewCookie    = 5
	ntsRecServerNeg    = 6
	ntsRecPortNeg      = 7
	ntsCritical        = 0x8000

	ntsNextProtoNTPv4 = 0  // protocol id for NTPv4
	ntsAEADAesSiv256  = 15 // AEAD_AES_SIV_CMAC_256 (the mandatory algorithm)
)

func (n *nts) Handle(ctx context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	withTimeout(conn, cfg.ReadTimeout)
	res := Result{Meta: map[string]any{}}
	if n.mgr == nil {
		// NTS-KE is TLS-only; without a cert manager we can't terminate it.
		res.Meta["tls_err"] = "no cert manager (data_dir unset)"
		return res, nil
	}

	tcfg, err := n.mgr.serverConfig(cfg.ID, tlsHosts(cfg), n.arch)
	if err != nil {
		res.Meta["cert_err"] = err.Error()
		return res, nil
	}
	// NTS-KE is identified by ALPN "ntske/1"; advertise it so a conformant
	// client proceeds (and so our ServerHello carries the right ALPN).
	tcfg.NextProtos = []string{"ntske/1"}

	// Peek the ClientHello for JA3/JA4 before crypto/tls consumes it.
	peeker := newPeekConn(conn)
	ja3Hash, ja3Raw, ja4 := "", "", ""
	if ch, ok := peeker.peekClientHello(); ok {
		ja3Raw, ja3Hash = fingerprint.JA3(ch)
		ja4 = fingerprint.JA4(ch)
	}
	capConn := newCaptureConn(peeker, 4096)
	tlsConn := tls.Server(capConn, tcfg)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		res.Meta["tls_err"] = err.Error()
		addFP(res.Meta, ja3Hash, ja3Raw, ja4, "", "")
		flagAnomaly(&res, "nts-ke-probe")
		return res, nil
	}
	st := tlsConn.ConnectionState()
	res.Meta["tls"] = true
	res.Meta["tls_version"] = tlsVersionName(st.Version)
	if st.ServerName != "" {
		res.Meta["sni"] = st.ServerName
	}
	if st.NegotiatedProtocol != "" {
		res.Meta["alpn"] = st.NegotiatedProtocol
	}
	ja3sRaw, ja3sHash := "", ""
	if sh := capConn.serverHello(); sh != nil {
		ja3sRaw, ja3sHash = fingerprint.JA3S(sh)
	}
	addFP(res.Meta, ja3Hash, ja3Raw, ja4, ja3sHash, ja3sRaw)
	flagAnomaly(&res, "nts-ke-probe")
	setIfEmpty(res.Meta, "intent", "NTS-KE (Network Time Security) key establishment — secure-NTP bootstrap")

	// Read the client's NTS-KE record stream (bounded) and classify what it
	// offered. The record stream ends at the End-of-Message record.
	if proto, aeads, ok := n.readKERecords(tlsConn, &res); ok {
		if len(proto) > 0 {
			res.Meta["nts_next_protocols"] = proto
		}
		if len(aeads) > 0 {
			res.Meta["nts_aead_algorithms"] = aeads
		}
	}

	// Respond with NTPv4 + AES-SIV-CMAC-256 + 8 opaque cookies + end-of-message.
	if _, err := tlsConn.Write(n.buildKEResponse()); err != nil {
		res.Meta["write_err"] = err.Error()
	}
	res.BannerSent = "nts-ke response (ntpv4/aes-siv-cmac-256)"
	return res, nil
}

// readKERecords parses the client's NTS-KE record stream, returning the offered
// next-protocol IDs and AEAD algorithm IDs. Bounded by record count + size.
func (n *nts) readKERecords(conn net.Conn, res *Result) (protos, aeads []uint16, ok bool) {
	hdr := make([]byte, 4)
	for i := 0; i < 32; i++ {
		if _, err := io.ReadFull(conn, hdr); err != nil {
			return protos, aeads, len(protos) > 0 || len(aeads) > 0
		}
		recType := binary.BigEndian.Uint16(hdr[0:2]) &^ ntsCritical
		bodyLen := int(binary.BigEndian.Uint16(hdr[2:4]))
		if bodyLen > 1024 {
			return protos, aeads, false
		}
		body := make([]byte, bodyLen)
		if bodyLen > 0 {
			if _, err := io.ReadFull(conn, body); err != nil {
				return protos, aeads, false
			}
		}
		res.Payload = append(res.Payload, hdr...)
		res.Payload = append(res.Payload, body...)
		switch recType {
		case ntsRecNextProto:
			for j := 0; j+1 < len(body); j += 2 {
				protos = append(protos, binary.BigEndian.Uint16(body[j:j+2]))
			}
		case ntsRecAEAD:
			for j := 0; j+1 < len(body); j += 2 {
				aeads = append(aeads, binary.BigEndian.Uint16(body[j:j+2]))
			}
		case ntsRecEndOfMessage:
			return protos, aeads, true
		}
	}
	return protos, aeads, true
}

// buildKEResponse assembles the NTS-KE server response record stream.
func (n *nts) buildKEResponse() []byte {
	var out []byte
	rec := func(t uint16, body []byte) {
		h := make([]byte, 4)
		binary.BigEndian.PutUint16(h[0:2], t)
		binary.BigEndian.PutUint16(h[2:4], uint16(len(body)))
		out = append(out, h...)
		out = append(out, body...)
	}
	// Next Protocol Negotiation = NTPv4 (critical).
	np := make([]byte, 2)
	binary.BigEndian.PutUint16(np, ntsNextProtoNTPv4)
	rec(ntsRecNextProto|ntsCritical, np)
	// AEAD Algorithm Negotiation = AES-SIV-CMAC-256 (critical).
	ae := make([]byte, 2)
	binary.BigEndian.PutUint16(ae, ntsAEADAesSiv256)
	rec(ntsRecAEAD|ntsCritical, ae)
	// 8 opaque cookies (random; never honored on the NTP side).
	for i := 0; i < 8; i++ {
		cookie := make([]byte, 100)
		_, _ = crand.Read(cookie)
		rec(ntsRecNewCookie, cookie)
	}
	// End of Message (critical, empty).
	rec(ntsRecEndOfMessage|ntsCritical, nil)
	return out
}
