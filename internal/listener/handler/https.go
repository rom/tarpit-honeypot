package handler

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/fingerprint"
	"github.com/rom/tarpit-honeypot/internal/identity"
	"github.com/rom/tarpit-honeypot/internal/jitter"
)

type https struct {
	mu          sync.Mutex
	cache       map[string]*tls.Certificate
	dir         string
	urlCanaries []config.URLCanary
	id          *identity.Identity
	jit         *jitter.Jitterer
	rotateDays  int
}

func newHTTPS(dataDir string, rotateDays int) (*https, error) {
	dir := filepath.Join(dataDir, "tls")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, fmt.Errorf("https: mkdir %s: %w", dir, err)
	}
	return &https{cache: map[string]*tls.Certificate{}, dir: dir, rotateDays: rotateDays}, nil
}

func (h *https) Name() string { return "https" }

func (h *https) Handle(ctx context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	withTimeout(conn, cfg.ReadTimeout)
	h.jit.Sleep(ctx)
	hosts := cfg.HTTPS.Hosts
	if len(hosts) == 0 {
		hosts = []string{"localhost"}
	}
	cert, err := h.certFor(hosts)
	if err != nil {
		return Result{Meta: map[string]any{"cert_err": err.Error()}}, nil
	}

	// Peek the first TLS record so we can compute JA3/JA4 from the
	// ClientHello before crypto/tls consumes it. peekConn replays the
	// peeked bytes back into the stream for the real handshake.
	peeker := newPeekConn(conn)
	ja3Hash, ja4, ja3Raw := "", "", ""
	if ch, ok := peeker.peekClientHello(); ok {
		raw, sum := fingerprint.JA3(ch)
		ja3Hash = sum
		ja3Raw = raw
		ja4 = fingerprint.JA4(ch)
	}

	tlsConn := tls.Server(peeker, &tls.Config{
		Certificates: []tls.Certificate{*cert},
		MinVersion:   tls.VersionTLS12,
	})
	if err := tlsConn.HandshakeContext(context.Background()); err != nil {
		meta := map[string]any{"tls_err": err.Error()}
		if ja3Hash != "" {
			meta["ja3"] = ja3Hash
			meta["ja3_raw"] = ja3Raw
		}
		if ja4 != "" {
			meta["ja4"] = ja4
		}
		return Result{Meta: meta}, nil
	}
	state := tlsConn.ConnectionState()
	res, _ := serveHTTP(tlsConn, cfg, h.urlCanaries, h.id)
	if res.Meta == nil {
		res.Meta = map[string]any{}
	}
	res.Meta["tls_version"] = tlsVersionName(state.Version)
	res.Meta["sni"] = state.ServerName
	if ja3Hash != "" {
		res.Meta["ja3"] = ja3Hash
		res.Meta["ja3_raw"] = ja3Raw
	}
	if ja4 != "" {
		res.Meta["ja4"] = ja4
	}
	return res, nil
}

func (h *https) certFor(hosts []string) (*tls.Certificate, error) {
	key := ""
	for _, x := range hosts {
		key += x + "|"
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if c, ok := h.cache[key]; ok && !h.shouldRotate(c) {
		return c, nil
	}
	// Try to load from disk first — and rotate if the on-disk cert is
	// older than the configured window.
	certPath := filepath.Join(h.dir, safeFilename(key)+".crt")
	keyPath := filepath.Join(h.dir, safeFilename(key)+".key")
	if c, err := tls.LoadX509KeyPair(certPath, keyPath); err == nil && !h.shouldRotate(&c) {
		h.cache[key] = &c
		return &c, nil
	}
	c, err := generateSelfSigned(hosts)
	if err != nil {
		return nil, err
	}
	if err := writeCert(certPath, keyPath, c); err != nil {
		return nil, err
	}
	h.cache[key] = c
	return c, nil
}

// shouldRotate reports whether the cert is older than the configured
// rotateDays. The check uses NotBefore so it doesn't depend on the
// far-future NotAfter.
func (h *https) shouldRotate(c *tls.Certificate) bool {
	if h.rotateDays <= 0 || c == nil {
		return false
	}
	if c.Leaf == nil && len(c.Certificate) > 0 {
		parsed, err := x509.ParseCertificate(c.Certificate[0])
		if err != nil {
			return false
		}
		c.Leaf = parsed
	}
	if c.Leaf == nil {
		return false
	}
	age := time.Since(c.Leaf.NotBefore)
	return age > time.Duration(h.rotateDays)*24*time.Hour
}

func generateSelfSigned(hosts []string) (*tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	template := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: hosts[0]},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(2 * 365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, h)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, err
	}
	c := &tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  priv,
	}
	// Stash PEM forms for persistence in writeCert.
	c.Leaf, _ = x509.ParseCertificate(der)
	_ = keyDER // keyDER is used by writeCert via a separate marshal call
	return c, nil
}

func writeCert(certPath, keyPath string, c *tls.Certificate) error {
	priv, ok := c.PrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		return fmt.Errorf("writeCert: unexpected key type")
	}
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Certificate[0]})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(certPath, certPEM, 0o640); err != nil {
		return err
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return err
	}
	return nil
}

func safeFilename(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-', c == '.':
			out = append(out, c)
		default:
			out = append(out, '_')
		}
	}
	if len(out) == 0 {
		return "default"
	}
	return string(out)
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS1.0"
	case tls.VersionTLS11:
		return "TLS1.1"
	case tls.VersionTLS12:
		return "TLS1.2"
	case tls.VersionTLS13:
		return "TLS1.3"
	}
	return "unknown"
}
