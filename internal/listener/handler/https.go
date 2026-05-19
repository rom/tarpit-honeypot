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
)

type https struct {
	mu     sync.Mutex
	cache  map[string]*tls.Certificate
	dir    string
}

func newHTTPS(dataDir string) (*https, error) {
	dir := filepath.Join(dataDir, "tls")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, fmt.Errorf("https: mkdir %s: %w", dir, err)
	}
	return &https{cache: map[string]*tls.Certificate{}, dir: dir}, nil
}

func (h *https) Name() string { return "https" }

func (h *https) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	withTimeout(conn, cfg.ReadTimeout)
	hosts := cfg.HTTPS.Hosts
	if len(hosts) == 0 {
		hosts = []string{"localhost"}
	}
	cert, err := h.certFor(hosts)
	if err != nil {
		return Result{Meta: map[string]any{"cert_err": err.Error()}}, nil
	}
	tlsConn := tls.Server(conn, &tls.Config{
		Certificates: []tls.Certificate{*cert},
		MinVersion:   tls.VersionTLS12,
	})
	if err := tlsConn.HandshakeContext(context.Background()); err != nil {
		return Result{Meta: map[string]any{"tls_err": err.Error()}}, nil
	}
	state := tlsConn.ConnectionState()
	res, _ := serveHTTP(tlsConn, cfg)
	if res.Meta == nil {
		res.Meta = map[string]any{}
	}
	res.Meta["tls_version"] = tlsVersionName(state.Version)
	res.Meta["sni"] = state.ServerName
	return res, nil
}

func (h *https) certFor(hosts []string) (*tls.Certificate, error) {
	key := ""
	for _, x := range hosts {
		key += x + "|"
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if c, ok := h.cache[key]; ok {
		return c, nil
	}
	// Try to load from disk first.
	certPath := filepath.Join(h.dir, safeFilename(key)+".crt")
	keyPath := filepath.Join(h.dir, safeFilename(key)+".key")
	if c, err := tls.LoadX509KeyPair(certPath, keyPath); err == nil {
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
