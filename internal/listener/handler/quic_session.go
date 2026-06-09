package handler

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/fingerprint"
)

// HandleSession is the connection-oriented QUIC path, used when a listener sets
// udp_session. It is the first consumer of the per-source multi-datagram UDP
// session primitive and adds two capabilities the stateless single-datagram
// path (Handle) structurally cannot have:
//
//  1. Cross-datagram ClientHello reassembly. A ClientHello that doesn't fit one
//     Initial — increasingly common once a client offers post-quantum key
//     shares, ECH, or a long ALPN/extension set — is split across CRYPTO frames
//     in several Initial packets. Reading successive datagrams from the same
//     source lets us reassemble and fingerprint it, where the stateless path
//     sees only a fragment and gives up.
//
//  2. Address validation via a QUIC Retry (RFC 9000 §17.2.5 / RFC 9001 §5.8).
//     We answer the first (RFC-mandated >=1200-byte) Initial with a Retry — the
//     QUIC primitive purpose-built for anti-amplification: it is smaller than
//     the Initial it answers (never an amplifier) and forces the client to prove
//     its source address by echoing our token in a retried Initial. A source
//     that echoes the token cannot be a spoofed address, which is high-signal.
//
// What we deliberately do NOT do — and say so plainly — is complete the TLS 1.3
// handshake or decrypt 1-RTT HTTP/3 application data: that needs real (EC)DHE, a
// server certificate, and the full transcript, i.e. a live QUIC+TLS server,
// which this decoy stack is not (see docs/design.md §15). The 1-RTT packet
// protection in quic_1rtt.go is a tested foundation for that, not a live
// capability. So this captures everything recoverable from the handshake flight
// (JA3/JA4, SNI, ALPN, transport parameters, address validation) and stops.
func (q *quicH) HandleSession(ctx context.Context, sess *UDPSession, cfg config.Listener) (Result, error) {
	res := Result{Meta: map[string]any{"proto": "quic", "quic_session": true}}

	readTimeout := cfg.ReadTimeout
	if readTimeout <= 0 {
		readTimeout = 3 * time.Second
	}

	// CRYPTO chunks keyed by hex(packet DCID): a pre-Retry flight and the
	// retried flight use different DCIDs, so this keeps their ClientHellos from
	// colliding while still merging fragments within each flight.
	flights := map[string][]quicCryptoChunk{}
	var version uint32
	datagrams := 0
	consideredRetry := false
	retrySent := false
	var retryToken []byte
	var validatedDCID string

	const maxSessionDatagrams = 8
	for datagrams < maxSessionDatagrams {
		b, err := sess.Read(ctx, readTimeout)
		if err != nil {
			break
		}
		datagrams++
		if datagrams == 1 {
			res.Payload = append([]byte(nil), b...)
		}

		v, dcid, scid, _, ok := parseQUICLongHeader(b)
		if !ok {
			continue // short-header / non-QUIC datagram — nothing to fingerprint
		}
		if version == 0 {
			version = v
		}

		// A retried Initial that echoes the token we issued proves the source
		// received our Retry — its address is validated and cannot be spoofed.
		if retrySent && len(retryToken) > 0 && quicIsInitial(v, b[0]) {
			if tok, tok2 := quicInitialToken(b); tok2 && bytes.Equal(tok, retryToken) {
				res.Meta["quic_address_validated"] = true
				flagAnomaly(&res, "quic-address-validated")
				validatedDCID = hex.EncodeToString(dcid)
			}
		}

		// Decrypt this Initial and accumulate its CRYPTO frames under the
		// packet's own DCID.
		if _, pdcid, plaintext, dok := quicDecryptInitial(b); dok {
			key := hex.EncodeToString(pdcid)
			flights[key] = append(flights[key], quicCryptoChunks(plaintext)...)
		}

		// Issue a Retry once, on the first sufficiently large Initial, when the
		// reply policy permits. A Retry is sub-unity by construction, but it is
		// still an unsolicited reply to a spoofable source, so gate it like any
		// other amplifier reply.
		if !consideredRetry && quicIsInitial(v, b[0]) && len(b) >= 1200 {
			consideredRetry = true
			if handlerMuted(cfg.Handler) || !AmplifierReplyAllowed("quic", "retry", sess.Src) {
				res.Meta["quic_retry_suppressed"] = true
			} else {
				serverSCID := make([]byte, 8)
				_, _ = rand.Read(serverSCID)
				retryToken = make([]byte, 16)
				_, _ = rand.Read(retryToken)
				// Retry DCID = client SCID; the integrity tag binds the client's
				// DCID (ODCID).
				if pkt, bok := buildQUICRetry(v, dcid, scid, serverSCID, retryToken); bok {
					if _, werr := sess.Write(pkt); werr == nil {
						retrySent = true
						res.BannerSent = "quic retry"
						res.Meta["quic_retry_issued"] = true
						flagAnomaly(&res, "quic-retry-issued")
					}
				}
			}
			continue // wait for the retried Initial (or time out)
		}
	}

	res.Meta["quic_datagrams"] = datagrams
	if version != 0 {
		res.Meta["quic_version"] = quicVersionName(version)
	}
	if datagrams == 0 {
		return res, nil
	}
	flagAnomaly(&res, "quic-initial")
	if len(flights) > 0 {
		res.Meta["quic_flights"] = len(flights)
	}

	// Reassemble + fingerprint the best ClientHello across the flights, preferring
	// the address-validated one.
	ch := quicBestClientHello(flights, validatedDCID)
	if ch == nil {
		res.Meta["quic"] = "no-clienthello"
		return res, nil
	}
	if raw, hash := fingerprint.JA3(ch); hash != "" {
		res.Meta["ja3"] = hash
		res.Meta["ja3_raw"] = raw
	}
	if ja4 := fingerprint.JA4(ch); ja4 != "" {
		res.Meta["ja4"] = ja4
	}
	hi := parseQUICClientHello(ch)
	if hi.SNI != "" {
		res.Meta["quic_sni"] = hi.SNI
	}
	if len(hi.ALPN) > 0 {
		res.Meta["quic_alpn"] = hi.ALPN
	}
	if len(hi.TransportParam) > 0 {
		res.Meta["quic_transport_params"] = hi.TransportParam
	}
	if hi.HTTP3 {
		res.Meta["http3"] = true
		flagAnomaly(&res, "quic-http3")
	}
	return res, nil
}

// quicBestClientHello reassembles each flight's CRYPTO and returns the best
// ClientHello: the address-validated flight if it yields one, else the first
// flight whose reassembly is a TLS ClientHello (handshake type 0x01).
func quicBestClientHello(flights map[string][]quicCryptoChunk, preferDCID string) []byte {
	isCH := func(b []byte) bool { return len(b) >= 4 && b[0] == 0x01 }
	if preferDCID != "" {
		if ch := quicReassembleChunks(flights[preferDCID]); isCH(ch) {
			return ch
		}
	}
	for _, chunks := range flights {
		if ch := quicReassembleChunks(chunks); isCH(ch) {
			return ch
		}
	}
	return nil
}
