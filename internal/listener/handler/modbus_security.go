package handler

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"net"

	"github.com/rom/tarpit-honeypot/internal/archetype"
	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/fingerprint"
)

// modbusSecurity emulates Modbus/TCP Security (the Modbus.org "MB/TCP Security"
// spec): the standard Modbus MBAP/PDU exchange wrapped in TLS on port 802, with
// mutual-TLS client-certificate authentication that carries the client's role
// in a custom X.509 extension. We terminate TLS (requesting — but not requiring
// — a client cert so a scanner without one still completes the handshake),
// compute JA3/JA4/JA3S like the other TLS-fronted services, capture the client
// certificate subject + the Modbus role, flag the secure-Modbus session, and
// then run the normal `modbus` PDU handler over the encrypted channel so
// reads/writes/diagnostics are classified exactly as on plaintext 502.
type modbusSecurity struct {
	mgr   *certManager
	arch  *archetype.Profile
	inner Handler
}

// modbusRoleOID is the Modbus Security "role" X.509 certificate-extension OID
// (Modbus.org PEN 50316, MB/TCP Security spec): 1.3.6.1.4.1.50316.802.1.
var modbusRoleOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 50316, 802, 1}

func newModbusSecurity(deps Deps) (Handler, error) {
	mgr, err := newCertManager(deps.DataDir, deps.TLSRotate, deps.Identity)
	if err != nil {
		return nil, err
	}
	return &modbusSecurity{mgr: mgr, arch: deps.Archetype, inner: &modbus{}}, nil
}

func (m *modbusSecurity) Name() string { return "modbus_security" }

func (m *modbusSecurity) Handle(ctx context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	withTimeout(conn, cfg.ReadTimeout)
	tcfg, err := m.mgr.serverConfig(cfg.ID, tlsHosts(cfg), m.arch)
	if err != nil {
		return Result{Meta: map[string]any{"cert_err": err.Error()}}, nil
	}
	tcfg = tcfg.Clone()
	tcfg.ClientAuth = tls.RequestClientCert // capture the role cert if offered

	peeker := newPeekConn(conn)
	ja3Hash, ja3Raw, ja4 := "", "", ""
	if ch, ok := peeker.peekClientHello(); ok {
		ja3Raw, ja3Hash = fingerprint.JA3(ch)
		ja4 = fingerprint.JA4(ch)
	}
	capConn := newCaptureConn(peeker, 4096)
	tlsConn := tls.Server(capConn, tcfg)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		meta := map[string]any{"tls_err": err.Error(), "non_modbus_security": true}
		addFP(meta, ja3Hash, ja3Raw, ja4, "", "")
		return Result{Meta: meta}, nil
	}

	state := tlsConn.ConnectionState()
	res, herr := m.inner.Handle(ctx, tlsConn, cfg)
	if res.Meta == nil {
		res.Meta = map[string]any{}
	}
	res.Meta["tls"] = true
	res.Meta["tls_version"] = tlsVersionName(state.Version)
	if state.ServerName != "" {
		res.Meta["sni"] = state.ServerName
	}
	flagAnomaly(&res, "modbus-secure-session")
	setIfEmpty(res.Meta, "intent", "Modbus/TCP Security (TLS) — authenticated PLC access on 802")
	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		res.Meta["client_cert_subject"] = cert.Subject.String()
		if role := modbusCertRole(cert); role != "" {
			res.Meta["modbus_role"] = role
		}
	} else {
		// A real Modbus Security server requires a client cert; a TLS session
		// with none is a scanner / misconfigured client probing 802.
		flagAnomaly(&res, "modbus-secure-no-clientcert")
	}
	ja3sRaw, ja3sHash := "", ""
	if sh := capConn.serverHello(); sh != nil {
		ja3sRaw, ja3sHash = fingerprint.JA3S(sh)
	}
	addFP(res.Meta, ja3Hash, ja3Raw, ja4, ja3sHash, ja3sRaw)
	return res, herr
}

// modbusCertRole returns the role carried in the Modbus Security role extension
// of a client certificate, or "" when the extension is absent.
func modbusCertRole(cert *x509.Certificate) string {
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(modbusRoleOID) {
			var role string
			if _, err := asn1.Unmarshal(ext.Value, &role); err == nil && role != "" {
				return role
			}
			return string(ext.Value) // fall back to the raw bytes
		}
	}
	return ""
}
