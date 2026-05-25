package handler

import (
	"context"
	"crypto/tls"
	"net"

	"github.com/rom/tarpit-honeypot/internal/archetype"
	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/fingerprint"
)

// tlsWrap turns any plaintext handler into its implicit-TLS variant (the way
// imaps/pop3s/smtps sit on 993/995/465 next to imap/pop3/smtp on 143/110/25):
// it performs the TLS handshake, computes JA3/JA4 (from the ClientHello) and
// JA3S (from our ServerHello) like the https handler, then runs the inner
// protocol handler over the encrypted connection. This is what closes the "TLS
// only on https" gap for the mail/directory/IoT services without duplicating
// each protocol.
type tlsWrap struct {
	inner Handler
	mgr   *certManager
	arch  *archetype.Profile
	name  string
}

func newTLSWrap(innerName, publicName string, deps Deps) (Handler, error) {
	inner, err := Get(innerName, deps)
	if err != nil {
		return nil, err
	}
	mgr, err := newCertManager(deps.DataDir, deps.TLSRotate, deps.Identity)
	if err != nil {
		return nil, err
	}
	return &tlsWrap{inner: inner, mgr: mgr, arch: deps.Archetype, name: publicName}, nil
}

func (w *tlsWrap) Name() string { return w.name }

func (w *tlsWrap) Handle(ctx context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	withTimeout(conn, cfg.ReadTimeout)
	tcfg, err := w.mgr.serverConfig(cfg.ID, tlsHosts(cfg), w.arch)
	if err != nil {
		return Result{Meta: map[string]any{"cert_err": err.Error()}}, nil
	}

	// Peek the ClientHello for JA3/JA4 before crypto/tls consumes it; capture
	// the outbound ServerHello for JA3S.
	peeker := newPeekConn(conn)
	ja3Hash, ja3Raw, ja4 := "", "", ""
	if ch, ok := peeker.peekClientHello(); ok {
		ja3Raw, ja3Hash = fingerprint.JA3(ch)
		ja4 = fingerprint.JA4(ch)
	}
	capConn := newCaptureConn(peeker, 4096)
	tlsConn := tls.Server(capConn, tcfg)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		meta := map[string]any{"tls_err": err.Error()}
		addFP(meta, ja3Hash, ja3Raw, ja4, "", "")
		return Result{Meta: meta}, nil
	}

	state := tlsConn.ConnectionState()
	res, herr := w.inner.Handle(ctx, tlsConn, cfg)
	if res.Meta == nil {
		res.Meta = map[string]any{}
	}
	res.Meta["tls"] = true
	res.Meta["tls_version"] = tlsVersionName(state.Version)
	if state.ServerName != "" {
		res.Meta["sni"] = state.ServerName
	}
	ja3sRaw, ja3sHash := "", ""
	if sh := capConn.serverHello(); sh != nil {
		ja3sRaw, ja3sHash = fingerprint.JA3S(sh)
	}
	addFP(res.Meta, ja3Hash, ja3Raw, ja4, ja3sHash, ja3sRaw)
	return res, herr
}

// addFP merges any computed TLS fingerprints into a meta map.
func addFP(meta map[string]any, ja3, ja3Raw, ja4, ja3s, ja3sRaw string) {
	if ja3 != "" {
		meta["ja3"] = ja3
		meta["ja3_raw"] = ja3Raw
	}
	if ja4 != "" {
		meta["ja4"] = ja4
	}
	if ja3s != "" {
		meta["ja3s"] = ja3s
		meta["ja3s_raw"] = ja3sRaw
	}
}
