package handler

import (
	"crypto/tls"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/rom/tarpit-honeypot/internal/archetype"
	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/identity"
)

// certManager generates and caches self-signed certificates for the TLS-bearing
// handlers beyond https: the implicit-TLS services (imaps / pop3s / smtps /
// ldaps / mqtts / ftps) and the PostgreSQL SSLRequest upgrade. It reuses the
// same on-disk format, per-service subject/key spread, and rotation as the
// https handler so every TLS service on a sensor shares one coherent cert store.
type certManager struct {
	mu         sync.Mutex
	cache      map[string]*tls.Certificate
	created    map[string]time.Time
	dir        string
	rotateDays int
	id         *identity.Identity
}

func newCertManager(dataDir string, rotateDays int, id *identity.Identity) (*certManager, error) {
	dir := filepath.Join(dataDir, "tls")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, fmt.Errorf("tls: mkdir %s: %w", dir, err)
	}
	return &certManager{
		cache: map[string]*tls.Certificate{}, created: map[string]time.Time{},
		dir: dir, rotateDays: rotateDays, id: id,
	}, nil
}

func (m *certManager) expired(created time.Time) bool {
	if m.rotateDays <= 0 || created.IsZero() {
		return false
	}
	return time.Since(created) > time.Duration(m.rotateDays)*24*time.Hour
}

// certFor returns a cached, on-disk, or freshly-generated cert for a profile —
// the same load-or-generate-then-cache flow the https handler uses.
func (m *certManager) certFor(prof certProfile) (*tls.Certificate, error) {
	key := prof.listenerID + "|" + prof.cn + "|" + prof.org + "|" + prof.keyType + "|"
	for _, x := range prof.hosts {
		key += x + "|"
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if c, ok := m.cache[key]; ok && !m.expired(m.created[key]) {
		return c, nil
	}
	certPath := filepath.Join(m.dir, safeFilename(key)+".crt")
	keyPath := filepath.Join(m.dir, safeFilename(key)+".key")
	if c, err := tls.LoadX509KeyPair(certPath, keyPath); err == nil {
		if mt := fileModTime(certPath); !m.expired(mt) {
			m.cache[key] = &c
			m.created[key] = mt
			return &c, nil
		}
	}
	c, err := generateSelfSignedProfile(prof, m.id)
	if err != nil {
		return nil, err
	}
	if err := writeCert(certPath, keyPath, c); err != nil {
		return nil, err
	}
	m.cache[key] = c
	m.created[key] = time.Now()
	return c, nil
}

// serverConfig builds a *tls.Config for a service, applying an archetype's TLS
// posture (weak ciphers / old protocol versions) when present so the handshake
// matches the decoy's advertised age.
func (m *certManager) serverConfig(listenerID string, hosts []string, arch *archetype.Profile) (*tls.Config, error) {
	if len(hosts) == 0 {
		hosts = []string{"localhost"}
	}
	prof := certProfile{
		listenerID: listenerID,
		hosts:      hosts,
		cn:         hosts[0],
		org:        deriveOrg(m.id, listenerID),
		keyType:    deriveKeyType(m.id, listenerID),
	}
	cert, err := m.certFor(prof)
	if err != nil {
		return nil, err
	}
	cfg := &tls.Config{Certificates: []tls.Certificate{*cert}, MinVersion: tls.VersionTLS12}
	if arch != nil {
		applyTLSPosture(cfg, arch.TLS())
	}
	return cfg, nil
}

// tlsHosts resolves the cert SANs for a listener: explicit https.hosts win,
// else a localhost default.
func tlsHosts(cfg config.Listener) []string {
	if len(cfg.HTTPS.Hosts) > 0 {
		return cfg.HTTPS.Hosts
	}
	return []string{"localhost"}
}
