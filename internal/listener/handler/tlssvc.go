package handler

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
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
// Process-wide deployment TLS identity. Set once at startup from
// sensor.tls_domain / sensor.tls_org (see SetTLSDefaults) and read-only
// thereafter, so every TLS-bearing service on the host presents a *consistent*
// certificate identity — the admin's real name/domain — instead of the old
// per-service "localhost" default. Empty values preserve the prior behavior.
var (
	defaultTLSDomain string
	defaultTLSOrg    string
	// deploymentDNSDomain is the sensor.domain value, mirrored here so the
	// handler functions that don't carry an *identity (e.g. the NTLM challenge
	// builders) can still answer with a consistent domain. Set once at startup.
	deploymentDNSDomain string
)

// SetDeploymentDomain mirrors sensor.domain into the handler package for the
// id-less response builders. Empty leaves the per-function defaults in place.
func SetDeploymentDomain(d string) {
	deploymentDNSDomain = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(d), "."))
}

// deploymentDomainOr returns the configured deployment domain, or fallback.
func deploymentDomainOr(fallback string) string {
	if deploymentDNSDomain != "" {
		return deploymentDNSDomain
	}
	return fallback
}

// netbiosDomain derives a NetBIOS-style (uppercase, <=15 char, first-label)
// domain name from the deployment domain, e.g. "corp.example.com" -> "CORP".
func netbiosDomain(fallback string) string {
	d := deploymentDNSDomain
	if d == "" {
		return fallback
	}
	if i := strings.IndexByte(d, '.'); i > 0 {
		d = d[:i]
	}
	d = strings.ToUpper(d)
	if len(d) > 15 {
		d = d[:15]
	}
	return d
}

// SetTLSDefaults installs the deployment-wide certificate CN/SAN domain and
// organization used as the fallback for any TLS service that doesn't pin its
// own https.hosts / https.cn / https.org. Call once before listeners start.
func SetTLSDefaults(domain, org string) {
	defaultTLSDomain = strings.TrimSpace(domain)
	defaultTLSOrg = strings.TrimSpace(org)
}

// defaultCertHost returns the deployment TLS domain, or "localhost" when none
// is configured.
func defaultCertHost() string {
	if defaultTLSDomain != "" {
		return defaultTLSDomain
	}
	return "localhost"
}

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
		hosts = []string{defaultCertHost()}
	}
	org := deriveOrg(m.id, listenerID)
	if defaultTLSOrg != "" {
		org = defaultTLSOrg // deployment-wide org for a consistent cert identity
	}
	prof := certProfile{
		listenerID: listenerID,
		hosts:      hosts,
		cn:         hosts[0],
		org:        org,
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
	return []string{defaultCertHost()}
}

// maybeCertMgr builds a cert manager from deps, or nil when no data dir is
// configured (some module-mode callers) or the dir can't be created — handlers
// then fall back to refusing STARTTLS / SSL rather than failing to start.
func maybeCertMgr(deps Deps) *certManager {
	if deps.DataDir == "" {
		return nil
	}
	m, err := newCertManager(deps.DataDir, deps.TLSRotate, deps.Identity)
	if err != nil {
		return nil
	}
	return m
}

// startTLS upgrades an already-greeted plaintext connection to TLS (the STARTTLS
// flow). The caller must have written the protocol's "ready" line first. On
// success the caller MUST build a fresh reader over the returned conn: any bytes
// a previous buffered reader had read ahead are intentionally dropped, which is
// the defense against STARTTLS command-injection (plaintext pipelined after the
// STARTTLS command must never be executed post-upgrade).
func startTLS(ctx context.Context, conn net.Conn, mgr *certManager, listenerID string, hosts []string, arch *archetype.Profile) (net.Conn, error) {
	tcfg, err := mgr.serverConfig(listenerID, hosts, arch)
	if err != nil {
		return nil, err
	}
	tlsConn := tls.Server(conn, tcfg)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	return tlsConn, nil
}

// alreadyTLS reports whether a connection is already a TLS server connection —
// used so the implicit-TLS variants (imaps/pop3s/smtps) refuse a pointless
// STARTTLS-inside-TLS instead of attempting a nested handshake.
func alreadyTLS(conn net.Conn) bool {
	_, ok := conn.(*tls.Conn)
	return ok
}
