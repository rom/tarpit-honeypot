package handler

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
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

	"github.com/rom/tarpit-honeypot/internal/archetype"
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
	arch        *archetype.Profile
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
	prof := h.profileFor(cfg)
	cert, err := h.certFor(prof)
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

	// TLS posture: an old archetype (Windows Server 2008, legacy
	// SCALANCE) deliberately negotiates old protocols + weak ciphers
	// so the handshake matches its ancient-firmware banner. Without an
	// archetype we keep the modern TLS 1.2+ default.
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{*cert},
		MinVersion:   tls.VersionTLS12,
	}
	if h.arch != nil {
		applyTLSPosture(tlsCfg, h.arch.TLS())
	}
	tlsConn := tls.Server(peeker, tlsCfg)
	// Use the caller's ctx (sensor-shutdown + per-listener cancellation
	// flow through it) instead of Background, so a slow-handshake
	// drip can be interrupted at process exit rather than burning a
	// goroutine until the per-conn ReadDeadline fires.
	if err := tlsConn.HandshakeContext(ctx); err != nil {
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
	res, _ := serveHTTP(tlsConn, cfg, h.urlCanaries, h.id, h.arch)
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

// certProfile is the resolved, service-unique parameters for one TLS
// endpoint's self-signed certificate.
type certProfile struct {
	listenerID string
	hosts      []string
	cn         string
	org        string
	ou         string
	keyType    string // "ecdsa" | "rsa"
}

// profileFor resolves the certProfile for a listener: explicit config
// fields win; blank fields fall back to deployment+service-derived
// defaults so two services on one sensor present distinct
// organizations / common names / key types even with no extra config.
func (h *https) profileFor(cfg config.Listener) certProfile {
	hs := cfg.HTTPS.Hosts
	if len(hs) == 0 {
		hs = []string{"localhost"}
	}
	p := certProfile{
		listenerID: cfg.ID,
		hosts:      hs,
		cn:         cfg.HTTPS.CN,
		org:        cfg.HTTPS.Org,
		ou:         cfg.HTTPS.OU,
		keyType:    cfg.HTTPS.KeyType,
	}
	if p.cn == "" {
		p.cn = hs[0]
	}
	if p.org == "" {
		p.org = h.deriveOrg(cfg.ID)
	}
	if p.keyType == "" {
		p.keyType = h.deriveKeyType(cfg.ID)
	}
	return p
}

// deriveOrg picks a believable organization name deterministically from
// the deployment seed + listener id, so each service's cert looks like
// it belongs to a distinct (fake) company.
func (h *https) deriveOrg(listenerID string) string {
	pool := []string{
		"Internal Services", "IT Department", "Acme Corp", "Contoso Ltd",
		"Globex", "Initech", "Umbrella Systems", "Northwind Traders",
		"Default Company Ltd", "",
	}
	if h.id == nil {
		return pool[0]
	}
	idx := int(h.id.Derive("tls-org/"+listenerID).Uint32("pick")) % len(pool)
	return pool[idx]
}

// deriveKeyType picks ecdsa or rsa per service so a TLS-fingerprinting
// scanner sees a mix of key algorithms across the host's services.
func (h *https) deriveKeyType(listenerID string) string {
	if h.id == nil {
		return "ecdsa"
	}
	if h.id.Derive("tls-keytype/"+listenerID).Uint32("pick")%4 == 0 {
		return "rsa" // ~25% of services present an RSA cert
	}
	return "ecdsa"
}

func (h *https) certFor(prof certProfile) (*tls.Certificate, error) {
	// Cache + on-disk key includes the listener id + subject so two
	// services with the same hostnames still get distinct certs.
	key := prof.listenerID + "|" + prof.cn + "|" + prof.org + "|" + prof.keyType + "|"
	for _, x := range prof.hosts {
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
	c, err := generateSelfSignedProfile(prof, h.id)
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

// generateSelfSignedProfile builds a self-signed cert from a resolved
// service profile. The key type (ECDSA P-256 or RSA-2048), subject
// (CN / O / OU), and validity-window jitter are all profile-driven so
// distinct services present distinct certificates. When id is non-nil
// the validity NotBefore is shifted by a deployment+service-derived
// offset so two sensors don't issue certs with identical timestamps.
func generateSelfSignedProfile(prof certProfile, id *identity.Identity) (*tls.Certificate, error) {
	var priv crypto.Signer
	var pub any
	switch prof.keyType {
	case "rsa":
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, err
		}
		priv, pub = k, &k.PublicKey
	default: // ecdsa
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		priv, pub = k, &k.PublicKey
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}

	subject := pkix.Name{CommonName: prof.cn}
	if prof.org != "" {
		subject.Organization = []string{prof.org}
	}
	if prof.ou != "" {
		subject.OrganizationalUnit = []string{prof.ou}
	}

	// Per-service validity jitter: shift NotBefore back by a stable
	// number of days so a scanner correlating cert ages across the
	// host's services sees different issue dates per endpoint.
	ageDays := 30
	if id != nil {
		ageDays = 7 + int(id.Derive("tls-age/"+prof.listenerID).Uint32("days")%700)
	}
	notBefore := time.Now().Add(-time.Duration(ageDays) * 24 * time.Hour)

	template := x509.Certificate{
		SerialNumber: serial,
		Subject:      subject,
		NotBefore:    notBefore,
		NotAfter:     notBefore.Add(2 * 365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, host := range prof.hosts {
		if ip := net.ParseIP(host); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, host)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, pub, priv)
	if err != nil {
		return nil, err
	}
	c := &tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  priv,
	}
	c.Leaf, _ = x509.ParseCertificate(der)
	return c, nil
}

// applyTLSPosture downgrades a tls.Config to match an archetype's
// declared posture. WeakCiphers re-enables the legacy CBC/3DES/RC4-era
// suites Go normally hides, so an old device negotiates the old
// ciphers a real one would. MinVersion is lowered to TLS 1.0 when
// weak ciphers are requested (those suites don't exist in TLS 1.3).
func applyTLSPosture(cfg *tls.Config, p archetype.TLSPosture) {
	if p.MaxVersion != 0 {
		cfg.MaxVersion = p.MaxVersion
	}
	if p.MinVersion != 0 {
		cfg.MinVersion = p.MinVersion
	}
	if p.WeakCiphers {
		if cfg.MinVersion == 0 || cfg.MinVersion > tls.VersionTLS10 {
			cfg.MinVersion = tls.VersionTLS10
		}
		if cfg.MaxVersion == 0 || cfg.MaxVersion > tls.VersionTLS12 {
			cfg.MaxVersion = tls.VersionTLS12
		}
		// Offer the legacy suites (incl. the insecure ones Go gates
		// behind CipherSuites explicitly) so a scanner sees the weak
		// posture an old box would present.
		cfg.CipherSuites = []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
		}
	}
}

func writeCert(certPath, keyPath string, c *tls.Certificate) error {
	var keyPEM []byte
	switch priv := c.PrivateKey.(type) {
	case *ecdsa.PrivateKey:
		keyDER, err := x509.MarshalECPrivateKey(priv)
		if err != nil {
			return err
		}
		keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	case *rsa.PrivateKey:
		keyDER := x509.MarshalPKCS1PrivateKey(priv)
		keyPEM = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyDER})
	default:
		return fmt.Errorf("writeCert: unexpected key type %T", c.PrivateKey)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Certificate[0]})
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
