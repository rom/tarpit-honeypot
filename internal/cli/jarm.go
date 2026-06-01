package cli

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"net"
	"time"

	"github.com/rom/tarpit-honeypot/internal/fingerprint"
)

// cmdJARM actively probes a TLS server and prints its JARM fingerprint. JARM
// is an active-probe server fingerprint: the scanner opens several TLS
// connections with deliberately varied ClientHellos and records how the
// server negotiates each. Point it at your own sensor's https listener to
// confirm its TLS posture matches the product it impersonates (and hasn't
// drifted), or at any TLS endpoint to fingerprint it.
//
// We drive ten probes that vary the offered TLS version range and cipher
// preference, and read the negotiated version / cipher / ALPN from
// crypto/tls's ConnectionState — no raw ServerHello parsing needed — then
// feed them to fingerprint.JARM.
func cmdJARM(args []string) error {
	fs := flag.NewFlagSet("jarm", flag.ContinueOnError)
	timeout := fs.Duration("timeout", 5*time.Second, "per-probe dial+handshake timeout")
	sni := fs.String("sni", "", "ServerName (SNI) to send; empty = none")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: jarm [--timeout D] [--sni NAME] <host:port>")
	}
	target := fs.Arg(0)
	if _, _, err := net.SplitHostPort(target); err != nil {
		return fmt.Errorf("target must be host:port: %w", err)
	}

	probes := make([]fingerprint.JARMProbe, len(jarmProbeConfigs))
	for i, pc := range jarmProbeConfigs {
		probes[i] = runJARMProbe(target, *sni, pc, *timeout)
	}
	fmt.Println(fingerprint.JARM(probes))
	return nil
}

// jarmProbeConfig is one JARM probe's TLS parameters.
type jarmProbeConfig struct {
	minVersion uint16
	maxVersion uint16
	ciphers    []uint16
	alpn       []string
}

// jarmProbeConfigs are the ten varied ClientHellos. This is a pragmatic
// approximation of the canonical JARM probe matrix: it varies the offered
// version window, the cipher ordering, and ALPN so a server's negotiation
// choices are exercised across the range. (The reference JARM also varies
// extension ordering and GREASE, which crypto/tls does not let us control;
// the resulting fingerprint is therefore self-consistent for drift detection
// rather than byte-identical to the upstream JARM corpus.)
var jarmProbeConfigs = []jarmProbeConfig{
	{tls.VersionTLS12, tls.VersionTLS13, nil, []string{"h2", "http/1.1"}},
	{tls.VersionTLS12, tls.VersionTLS13, nil, []string{"http/1.1"}},
	{tls.VersionTLS12, tls.VersionTLS12, nil, []string{"h2", "http/1.1"}},
	{tls.VersionTLS12, tls.VersionTLS12, nil, nil},
	{tls.VersionTLS13, tls.VersionTLS13, nil, []string{"h2"}},
	{tls.VersionTLS13, tls.VersionTLS13, nil, nil},
	{tls.VersionTLS10, tls.VersionTLS13, nil, []string{"http/1.1"}},
	{tls.VersionTLS10, tls.VersionTLS12, nil, nil},
	{tls.VersionTLS11, tls.VersionTLS13, nil, []string{"h2", "http/1.1"}},
	{tls.VersionTLS12, tls.VersionTLS13, []uint16{tls.TLS_AES_128_GCM_SHA256, tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256}, nil},
}

// runJARMProbe performs one probe and records the server's negotiation.
func runJARMProbe(target, sni string, pc jarmProbeConfig, timeout time.Duration) fingerprint.JARMProbe {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	d := &net.Dialer{}
	raw, err := d.DialContext(ctx, "tcp", target)
	if err != nil {
		return fingerprint.JARMProbe{} // Responded=false
	}
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(timeout))

	cfg := &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // fingerprinting, not trust
		MinVersion:         pc.minVersion,
		MaxVersion:         pc.maxVersion,
		ServerName:         sni,
		NextProtos:         pc.alpn,
	}
	if len(pc.ciphers) > 0 {
		cfg.CipherSuites = pc.ciphers
	}
	c := tls.Client(raw, cfg)
	if err := c.HandshakeContext(ctx); err != nil {
		return fingerprint.JARMProbe{} // server refused this probe (alert) — Responded=false
	}
	st := c.ConnectionState()
	return fingerprint.JARMProbe{
		Cipher:    st.CipherSuite,
		Version:   st.Version,
		ALPN:      st.NegotiatedProtocol,
		Responded: true,
	}
}
