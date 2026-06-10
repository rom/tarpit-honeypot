package handler

import (
	"context"
	"encoding/binary"
	"io"
	"net"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/safe"
)

// dnsTCP serves DNS over TCP (RFC 1035 §4.2.2, RFC 7766): every message is
// framed by a 2-byte big-endian length prefix. It reuses the UDP resolver's
// query parsing, tunneling/exfil heuristics, and topology-coherent answer
// builder — only the stream framing differs. DNS-over-TCP is itself a useful
// signal: resolvers fall back to TCP on truncated answers, and TCP is the
// transport for zone transfers (AXFR/IXFR) and large tunneling payloads, so a
// real authoritative-looking TCP responder draws out exactly that behaviour.
//
// A single connection may pipeline several queries; we answer a bounded number
// (then close) and capture the first one's name/type for the event metadata.
type dnsTCP struct{ inner *dnsHandler }

func newDNSTCP(deps Deps) *dnsTCP {
	return &dnsTCP{inner: &dnsHandler{id: deps.Identity, topo: deps.HoneynetView}}
}

func (d *dnsTCP) Name() string { return "dns" }

// SetHoneynetView lets the listener install topology data after construction
// (HoneynetAware), mirroring the UDP resolver.
func (d *dnsTCP) SetHoneynetView(v HoneynetSnapshot) { d.inner.topo = v }

// dnsTCPMaxQueries bounds the number of messages answered on one connection so
// a client can't pin a goroutine open indefinitely; the read deadline
// (cfg.ReadTimeout, applied via withTimeout) bounds the wait per message.
const dnsTCPMaxQueries = 8

func (d *dnsTCP) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	withTimeout(conn, cfg.ReadTimeout)
	res := Result{Meta: map[string]any{"transport": "tcp"}}

	var lenBuf [2]byte
	queries := 0
	for queries < dnsTCPMaxQueries {
		if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
			if queries == 0 {
				res.Meta["read_err"] = err.Error()
			}
			break
		}
		mlen := int(binary.BigEndian.Uint16(lenBuf[:])) // ≤ 65535
		if mlen == 0 {
			break
		}
		msg := make([]byte, mlen)
		if _, err := io.ReadFull(conn, msg); err != nil {
			res.Meta["read_err"] = err.Error()
			break
		}
		queries++
		// The first query drives the captured payload + event metadata.
		if queries == 1 {
			res.Payload = append([]byte(nil), msg...)
		}
		q, ok := parseDNSQuery(msg)
		if !ok {
			res.Meta["malformed_dns"] = true
			flagAnomaly(&res, "dns-malformed-query")
			res.Meta["intent"] = "malformed DNS query — parser fuzzing / evasion"
			break
		}
		if queries == 1 {
			res.Meta["qname"] = safe.SanitizeForLog(q.name)
			res.Meta["qtype"] = q.qtype
			res.Meta["qtype_name"] = dnsTypeName(q.qtype)
		}
		for _, a := range dnsQueryAnomalies(q.name, q.qtype, len(msg)) {
			flagAnomaly(&res, a)
		}
		dnsApplyDetections(&res, msg, q)
		// Zone transfer (AXFR 252 / IXFR 251): when fake_zone is enabled, serve a
		// fabricated juicy zone instead of refusing — a deception trap. (Over TCP
		// only; never a UDP amplifier.)
		if (q.qtype == 252 || q.qtype == 251) && cfg.DNS.FakeZone {
			for _, m := range d.inner.buildFakeZone(msg, q, cfg) {
				binary.BigEndian.PutUint16(lenBuf[:], uint16(len(m)))
				if _, err := conn.Write(lenBuf[:]); err != nil {
					res.Meta["write_err"] = err.Error()
					break
				}
				if _, err := conn.Write(m); err != nil {
					res.Meta["write_err"] = err.Error()
					break
				}
			}
			res.Meta["zone_transfer_served"] = true
			flagAnomaly(&res, "dns-zone-transfer-served")
			res.BannerSent = "dns AXFR (fake zone)"
			continue
		}
		reply := d.inner.buildAnswer(msg, q, cfg)
		if reply == nil {
			continue
		}
		binary.BigEndian.PutUint16(lenBuf[:], uint16(len(reply)))
		if _, err := conn.Write(lenBuf[:]); err != nil {
			res.Meta["write_err"] = err.Error()
			break
		}
		if _, err := conn.Write(reply); err != nil {
			res.Meta["write_err"] = err.Error()
			break
		}
		res.BannerSent = "dns answer (" + dnsTypeName(q.qtype) + ")"
	}
	res.Meta["dns_queries"] = queries
	_ = cfg
	return res, nil
}
