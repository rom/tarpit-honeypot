package handler

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"strings"
	"time"

	"github.com/rom/tarpit-honeypot/internal/archetype"
	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/cve"
	"github.com/rom/tarpit-honeypot/internal/egress"
	"github.com/rom/tarpit-honeypot/internal/fingerprint"
)

// errEgressUnavailable is returned when decrypt-and-forward is configured but no
// egress policy is installed — we fail closed rather than dial unrestricted.
var errEgressUnavailable = errors.New("tls_intercept: egress policy unavailable; refusing to forward")

// tlsIntercept terminates TLS with a believable cert (computing JA3/JA4/JA3S
// over the handshake) and then routes the decrypted stream one of two ways
// per the listener's tls_intercept config:
//
//   - inner handler: hand the cleartext to an internal protocol handler — a TLS
//     front for an emulated service on any port.
//   - forward: proxy the cleartext to a real backend (through the egress
//     allowlist), capturing BOTH directions — a true decrypt-and-forward MITM
//     that records the plaintext of an attacker<->real-service session.
//
// The forward mode is opt-in and egress-scoped: the backend must be in the
// egress allowlist, so the sensor can only proxy to destinations the operator
// permitted.
type tlsIntercept struct {
	mgr   *certManager
	arch  *archetype.Profile
	inner Handler // used when not forwarding
	tic   config.TLSIntercept
}

func newTLSIntercept(deps Deps, tic config.TLSIntercept) (Handler, error) {
	mgr, err := newCertManager(deps.DataDir, deps.TLSRotate, deps.Identity)
	if err != nil {
		return nil, err
	}
	t := &tlsIntercept{mgr: mgr, arch: deps.Archetype, tic: tic}
	if tic.ForwardTo == "" {
		innerName := tic.InnerHandler
		if innerName == "" {
			innerName = "raw"
		}
		inner, err := Get(innerName, deps)
		if err != nil {
			return nil, err
		}
		t.inner = inner
	}
	return t, nil
}

func (t *tlsIntercept) Name() string { return "tls_intercept" }

func (t *tlsIntercept) Handle(ctx context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	withTimeout(conn, cfg.ReadTimeout)
	tcfg, err := t.mgr.serverConfig(cfg.ID, tlsHosts(cfg), t.arch)
	if err != nil {
		return Result{Meta: map[string]any{"cert_err": err.Error()}}, nil
	}

	// Peek the ClientHello for JA3/JA4; capture the ServerHello for JA3S.
	peeker := newPeekConn(conn)
	ja3Hash, ja3Raw, ja4 := "", "", ""
	if ch, ok := peeker.peekClientHello(); ok {
		ja3Raw, ja3Hash = fingerprint.JA3(ch)
		ja4 = fingerprint.JA4(ch)
	}
	capConn := newCaptureConn(peeker, 4096)
	tlsConn := tls.Server(capConn, tcfg)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		meta := map[string]any{"tls_err": err.Error(), "tls_intercept": true}
		addFP(meta, ja3Hash, ja3Raw, ja4, "", "")
		return Result{Meta: meta}, nil
	}
	state := tlsConn.ConnectionState()
	meta := map[string]any{"tls": true, "tls_intercept": true, "tls_version": tlsVersionName(state.Version)}
	if state.ServerName != "" {
		meta["sni"] = state.ServerName
	}
	ja3sRaw, ja3sHash := "", ""
	if sh := capConn.serverHello(); sh != nil {
		ja3sRaw, ja3sHash = fingerprint.JA3S(sh)
	}
	addFP(meta, ja3Hash, ja3Raw, ja4, ja3sHash, ja3sRaw)

	if t.tic.ForwardTo == "" {
		// Mode A: hand the decrypted stream to the inner handler.
		res, herr := t.inner.Handle(ctx, tlsConn, cfg)
		if res.Meta == nil {
			res.Meta = map[string]any{}
		}
		for k, v := range meta {
			if _, exists := res.Meta[k]; !exists {
				res.Meta[k] = v
			}
		}
		return res, herr
	}

	// Mode B: decrypt-and-forward to a real backend through the egress
	// allowlist, capturing both directions.
	res := Result{Meta: meta}
	res.Meta["forward_to"] = t.tic.ForwardTo
	captured, err := t.forward(ctx, tlsConn, cfg)
	if err != nil {
		res.Meta["forward_err"] = err.Error()
		return res, nil
	}
	if len(captured) > 0 {
		res.Payload = captured
		// The whole point of decrypt-and-forward is to see what TLS was
		// hiding: run the cleartext the client sent to the backend through the
		// same exploit / credential / suspicious-URI detection the plaintext
		// handlers use, so an attack inside the tunnel is still attributed.
		t.analyzeDecrypted(&res, captured)
	}
	res.BannerSent = "tls_intercept forwarded " + t.tic.ForwardTo
	return res, nil
}

// analyzeDecrypted runs the decrypted client->backend bytes through CVE
// signature matching, suspicious-URI detection, and a light credential scan,
// flagging anomalies so an exploit or credential that arrived over TLS is
// attributed exactly as it would be on a plaintext handler.
func (t *tlsIntercept) analyzeDecrypted(res *Result, data []byte) {
	svc := t.tic.InnerHandler
	if svc == "" {
		svc = "http" // forward mode has no inner handler; assume an HTTP-shaped service
	}
	s := string(data)
	for _, rec := range cve.MatchPayload(svc, s) {
		res.CVEHits = appendUnique(res.CVEHits, rec.ID)
		flagAnomaly(res, "cve:"+rec.ID)
		flagAnomaly(res, "tls-decrypted-exploit")
	}
	// Reuse the HTTP suspicious-URI catalog against the cleartext request line.
	if m := suspiciousURI(s); m != "" {
		flagAnomaly(res, m)
		flagAnomaly(res, "tls-decrypted-exploit")
	}
	low := strings.ToLower(s)
	if strings.Contains(low, "authorization: basic ") || strings.Contains(low, "&password=") ||
		strings.Contains(low, "?password=") || strings.Contains(low, "\npassword=") {
		flagAnomaly(res, "tls-decrypted-credentials")
	}
}

// forward proxies the decrypted client stream to the configured backend
// (dialed through the egress allowlist) and copies both directions, returning
// the bytes the client sent (for the event payload/pcap). Bidirectional copy
// ends when either side closes.
func (t *tlsIntercept) forward(ctx context.Context, client net.Conn, cfg config.Listener) ([]byte, error) {
	pol := egress.Default()
	dctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	var backend net.Conn
	var err error
	if pol != nil {
		backend, err = pol.DialContext(dctx, "tcp", t.tic.ForwardTo)
	} else {
		// No egress policy installed → fail closed; never dial unrestricted.
		return nil, errEgressUnavailable
	}
	if err != nil {
		return nil, err
	}
	defer backend.Close()
	if t.tic.ForwardTLS {
		// Re-encrypt to the backend (TLS-to-TLS). Verification is skipped: we
		// are intercepting, not trusting, the backend's cert.
		bt := tls.Client(backend, &tls.Config{InsecureSkipVerify: true}) //nolint:gosec
		if err := bt.HandshakeContext(dctx); err != nil {
			return nil, err
		}
		backend = bt
	}

	// Capture client->backend bytes via a tee; copy backend->client straight.
	// When EITHER direction finishes, tear down both conns so the other copy
	// goroutine can't block forever: a backend that stays open-and-silent after
	// the client half-closes would otherwise park the backend->client copy — and
	// its goroutine + the backend fd + the client fd — indefinitely, leaking a
	// little on every such session until the process runs out of fds/memory.
	// The client conn carries an absolute read deadline (set in Handle), so the
	// client->backend copy always returns, which guarantees teardown.
	cap := &captureWriter{limit: 64 << 10}
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(backend, io.TeeReader(client, cap))
		if cw, ok := backend.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(client, backend)
		done <- struct{}{}
	}()
	<-done // first direction closed
	_ = backend.Close()
	_ = client.Close()
	<-done // second direction unblocks now that both conns are closed
	return cap.buf, nil
}

// captureWriter accumulates up to limit bytes (for the event payload), then
// silently drops the rest so a large transfer can't grow memory unbounded.
type captureWriter struct {
	buf   []byte
	limit int
}

func (c *captureWriter) Write(p []byte) (int, error) {
	if room := c.limit - len(c.buf); room > 0 {
		if len(p) <= room {
			c.buf = append(c.buf, p...)
		} else {
			c.buf = append(c.buf, p[:room]...)
		}
	}
	return len(p), nil
}
