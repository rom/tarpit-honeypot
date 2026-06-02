// Package identity manages per-deployment uniqueness. The sensor's
// deployment_id is a stable random seed that derives every "fixed" string
// the honeypot emits — SSH banner version suffixes, SMB challenge bytes,
// fake device serial numbers, hostnames in SMTP/IPMI responses, etc.
//
// Operators who deploy two sensors with their own deployment_id get two
// distinct fingerprints; Shodan-class scanners can't cluster them as
// "the same honeypot." The seed itself is recorded in a file under
// <data_dir>/.deployment-id so restarts don't shift fingerprints.
package identity

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	mathrand "math/rand"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

// Identity derives deterministic-but-deployment-unique strings/bytes from
// a seed. Methods are safe for concurrent use.
type Identity struct {
	seed string
	hash [32]byte

	mu       sync.Mutex
	smtpHost string
}

// Load reads the deployment id from <dataDir>/.deployment-id, generating
// one on first use. If `override` is non-empty, it's used directly and
// not persisted — useful for ephemeral containers where the ID should
// come from a config file or env var.
func Load(dataDir, override string) (*Identity, error) {
	if override != "" {
		return New(override), nil
	}
	path := filepath.Join(dataDir, ".deployment-id")
	b, err := os.ReadFile(path)
	if err == nil {
		s := strings.TrimSpace(string(b))
		if s != "" {
			return New(s), nil
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		// The file exists but we couldn't read it — don't silently regenerate
		// (and then fail to overwrite it), which masks the real cause. Surface
		// it with a fix, since this is the classic "owned by another user".
		return nil, fmt.Errorf("identity: read %s: %w%s", path, err, idPathHint(dataDir, path))
	}
	// Generate a 128-bit random id, hex-encoded.
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return nil, fmt.Errorf("identity: rand: %w", err)
	}
	id := hex.EncodeToString(buf)
	if err := os.MkdirAll(dataDir, 0o750); err != nil {
		return nil, fmt.Errorf("identity: mkdir %s: %w", dataDir, err)
	}
	if err := os.WriteFile(path, []byte(id+"\n"), 0o640); err != nil {
		return nil, fmt.Errorf("identity: write %s: %w%s", path, err, idPathHint(dataDir, path))
	}
	return New(id), nil
}

// idPathHint returns a parenthetical, actionable cause for a failure to read or
// write the deployment-id, since "permission denied" with no path or reason is
// useless when a hardened sensor won't start. The usual culprits: the data dir
// or the file was created by another user (e.g. an earlier run as root, now
// reopened as the dropped service account), or — on SELinux — the dir isn't
// labeled for the confined domain.
func idPathHint(dataDir, path string) string {
	uid := strconv.Itoa(os.Getuid())
	relabel := "; on SELinux also: restorecon -Rv " + dataDir
	if _, err := os.Stat(path); err == nil {
		return " (the file exists but isn't accessible to uid " + uid +
			" — likely created by another user, e.g. an earlier run as root; fix: chown it to the service account, e.g. chown <user>:<group> " + path + relabel + ")"
	}
	return " (uid " + uid + " cannot write in " + dataDir +
		" — check the data-dir ownership/permissions; fix: chown -R <user>:<group> " + dataDir + relabel + ")"
}

// New constructs an Identity from an existing seed string.
func New(seed string) *Identity {
	id := &Identity{seed: seed}
	id.hash = sha256.Sum256([]byte(seed))
	return id
}

// Seed returns the raw deployment_id (safe to log).
func (i *Identity) Seed() string { return i.seed }

// Derive returns a child Identity keyed by label. The deterministic seed
// mixes the parent seed with the label, so two children produce entirely
// different banner variants / hostnames / serial numbers. Used by the
// honeynet to give each artificial host its own stable identity.
func (i *Identity) Derive(label string) *Identity {
	mix := sha256.Sum256(append([]byte(label), i.hash[:]...))
	return &Identity{seed: i.seed + "/" + label, hash: mix}
}

// deterministicRand returns a *math/rand.Rand seeded with sha256(seed||label),
// so two calls with the same label produce the same numbers but different
// deployments diverge from byte 1.
func (i *Identity) deterministicRand(label string) *mathrand.Rand {
	mix := sha256.Sum256(append([]byte(label), i.hash[:]...))
	src := mathrand.NewSource(int64(binary.LittleEndian.Uint64(mix[:8])))
	return mathrand.New(src)
}

// SSHBannerVariant returns one of a small pool of plausible SSH banners,
// deterministic per deployment. The version + Debian-suffix combination
// varies so a scanner that hits 100 sensors sees ~10 distinct banners.
func (i *Identity) SSHBannerVariant() string {
	pool := []string{
		"SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u1",
		"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5",
		"SSH-2.0-OpenSSH_7.4",
		"SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3",
		"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6",
		"SSH-2.0-OpenSSH_9.6p1 Debian-4",
	}
	r := i.deterministicRand("ssh-banner")
	return pool[r.Intn(len(pool))]
}

// HTTPServerHeader returns a deployment-unique nginx-or-apache server header.
func (i *Identity) HTTPServerHeader() string {
	pool := []string{
		"nginx/1.18.0",
		"nginx/1.21.4",
		"nginx/1.24.0 (Ubuntu)",
		"Apache/2.4.41 (Ubuntu)",
		"Apache/2.4.52 (Debian)",
		"Microsoft-IIS/10.0",
	}
	r := i.deterministicRand("http-server")
	return pool[r.Intn(len(pool))]
}

// HostName returns a plausible hostname for SMTP banners, IPMI responses,
// etc. It looks like a normal corporate naming scheme.
func (i *Identity) HostName() string {
	prefixes := []string{"mail", "srv", "host", "fw", "edge", "core", "app"}
	r := i.deterministicRand("hostname")
	return fmt.Sprintf("%s%02d.example.internal", prefixes[r.Intn(len(prefixes))], 10+r.Intn(80))
}

// ApacheVersion returns a deployment-unique Apache httpd version
// string of the form "Apache/2.4.X (distro)". Used by the http /
// https handlers when emulating an Apache server. The pool spans the
// 2.2 and 2.4 lines + several distro flavors so a scanner hitting
// many sensors sees a believable spread of patch levels.
func (i *Identity) ApacheVersion() string {
	pool := []string{
		"Apache/2.4.62 (Debian)",
		"Apache/2.4.58 (Ubuntu)",
		"Apache/2.4.57 (Unix)",
		"Apache/2.4.54 (Red Hat Enterprise Linux)",
		"Apache/2.4.52 (Ubuntu)",
		"Apache/2.4.41 (Ubuntu)",
		"Apache/2.4.37 (centos)",
		"Apache/2.4.6 (CentOS)",
		"Apache/2.2.34 (Unix)",
		"Apache/2.2.15 (CentOS)",
	}
	r := i.deterministicRand("apache-version")
	return pool[r.Intn(len(pool))]
}

// ApacheModules returns a deployment-unique trailing module list that
// some Apache configs append to the Server header (e.g.
// "Apache/2.4.41 (Ubuntu) OpenSSL/1.1.1f mod_wsgi/4.6.8 Python/3.8").
// Returns "" for the (common) ServerTokens Prod / OS case.
func (i *Identity) ApacheModules() string {
	pool := []string{
		"",
		"",
		" OpenSSL/1.1.1f",
		" OpenSSL/3.0.2",
		" OpenSSL/1.1.1k mod_fcgid/2.3.9",
		" PHP/7.4.3",
		" mod_wsgi/4.6.8 Python/3.8",
		" OpenSSL/1.0.2k-fips mod_perl/2.0.11 Perl/v5.16.3",
	}
	r := i.deterministicRand("apache-modules")
	return pool[r.Intn(len(pool))]
}

// NginxVersion returns a deployment-unique nginx version string.
func (i *Identity) NginxVersion() string {
	pool := []string{
		"nginx/1.18.0 (Ubuntu)", "nginx/1.21.4", "nginx/1.24.0 (Ubuntu)",
		"nginx/1.25.3", "nginx/1.20.1", "nginx/1.14.2",
	}
	r := i.deterministicRand("nginx-version")
	return pool[r.Intn(len(pool))]
}

// FTPBannerVariant returns a deployment-unique FTP 220 banner.
func (i *Identity) FTPBannerVariant() string {
	pool := []string{
		"220 (vsFTPd 3.0.5)",
		"220 (vsFTPd 3.0.3)",
		"220 ProFTPD Server (Debian)",
		"220 Pure-FTPd server ready",
		"220 Microsoft FTP Service",
		"220 FileZilla Server 1.7.3",
	}
	r := i.deterministicRand("ftp-banner")
	return pool[r.Intn(len(pool))]
}

// DNSServerVersion returns a deployment-unique BIND version string
// (the classic `version.bind CH TXT` reconnaissance answer).
func (i *Identity) DNSServerVersion() string {
	pool := []string{
		"9.16.1-Ubuntu", "9.18.18-0ubuntu0.22.04.2", "9.11.4-P2-RedHat-9.11.4-26.P2.el7_9.13",
		"9.10.3-P4-Debian", "dnsmasq-2.80", "Microsoft DNS 6.1.7601 (1DB15CD4)",
	}
	r := i.deterministicRand("dns-version")
	return pool[r.Intn(len(pool))]
}

// NTPRefID returns a deployment-unique 4-byte NTP reference identifier
// (the upstream clock source shown in mode-4 replies). Stratum-2
// servers show the upstream server's IP; we synthesize a plausible
// one.
func (i *Identity) NTPRefID() [4]byte {
	b := i.Bytes("ntp-refid", 4)
	var out [4]byte
	copy(out[:], b)
	// Make it look like a routable upstream (avoid 0.x / 127.x / 10.x).
	if out[0] == 0 || out[0] == 127 || out[0] == 10 {
		out[0] = 17 + out[0]%200
	}
	return out
}

// ETagSeed returns a deployment-unique seed for synthesizing Apache/
// nginx ETag header values, so two sensors don't emit identical ETags
// for the same synthetic resource.
func (i *Identity) ETagSeed() uint32 { return i.Uint32("etag-seed") }

// SMTPGreetingProduct returns a deployment-unique SMTP product string
// for the 220 greeting (independent of the archetype path).
func (i *Identity) SMTPGreetingProduct() string {
	pool := []string{
		"Postfix", "Postfix (Ubuntu)", "Exim 4.94.2", "Sendmail 8.15.2/8.15.2",
		"Microsoft ESMTP MAIL Service", "OpenSMTPD",
	}
	r := i.deterministicRand("smtp-product")
	return pool[r.Intn(len(pool))]
}

// VNCVersion returns one of the real RFB protocol-version strings,
// deterministic per deployment. Different VNC servers (RealVNC,
// TightVNC, UltraVNC, the QEMU/libvirt built-in) advertise different
// RFB versions; varying ours defeats banner-clustering. The returned
// string includes the trailing newline the RFB handshake requires.
func (i *Identity) VNCVersion() string {
	pool := []string{
		"RFB 003.008\n", // 3.8 — most common (RealVNC, TigerVNC)
		"RFB 003.007\n", // 3.7
		"RFB 003.003\n", // 3.3 — older / embedded KVM-over-IP, libvirt
		"RFB 004.001\n", // 4.1 — Apple Remote Desktop advertises this
		"RFB 003.889\n", // Apple's quirky ARD version string
	}
	r := i.deterministicRand("vnc-version")
	return pool[r.Intn(len(pool))]
}

// SSHCookie returns the 16-byte random cookie an SSH server places in
// its KEXINIT. Deterministic per deployment so the HASSH-adjacent
// fingerprint of OUR side is also stable + unique.
func (i *Identity) SSHCookie() [16]byte {
	b := i.Bytes("ssh-kex-cookie", 16)
	var out [16]byte
	copy(out[:], b)
	return out
}

// MySQLVersion returns a deployment-unique MySQL version string.
func (i *Identity) MySQLVersion() string {
	pool := []string{
		"5.7.42-log",
		"5.7.44",
		"8.0.32-0ubuntu0.22.04.2",
		"8.0.36",
		"10.5.23-MariaDB-1:10.5.23+maria~ubu2004",
	}
	r := i.deterministicRand("mysql-version")
	return pool[r.Intn(len(pool))]
}

// RedisVersion returns a deployment-unique Redis version string, reported
// in the INFO server section so two sensors don't cluster on one banner.
func (i *Identity) RedisVersion() string {
	pool := []string{"6.0.16", "6.2.14", "7.0.15", "7.2.4", "7.4.1"}
	r := i.deterministicRand("redis-version")
	return pool[r.Intn(len(pool))]
}

// MemcachedVersion returns a deployment-unique memcached version string.
func (i *Identity) MemcachedVersion() string {
	pool := []string{"1.5.22", "1.6.18", "1.6.21", "1.6.31"}
	r := i.deterministicRand("memcached-version")
	return pool[r.Intn(len(pool))]
}

// MongoVersion returns a deployment-unique MongoDB version string, with the
// matching maxWireVersion the handshake should advertise for that release.
func (i *Identity) MongoVersion() (version string, maxWire int32) {
	pool := []struct {
		v    string
		wire int32
	}{
		{"4.4.29", 9},
		{"5.0.26", 13},
		{"6.0.14", 17},
		{"7.0.8", 21},
	}
	r := i.deterministicRand("mongo-version")
	p := pool[r.Intn(len(pool))]
	return p.v, p.wire
}

// ElasticVersion returns a deployment-unique Elasticsearch version string
// with its matching Lucene version.
func (i *Identity) ElasticVersion() (number, lucene string) {
	pool := []struct{ es, lc string }{
		{"7.10.2", "8.7.0"},
		{"7.17.0", "8.11.1"},
		{"8.6.2", "9.4.2"},
		{"8.11.3", "9.8.0"},
	}
	r := i.deterministicRand("elastic-version")
	p := pool[r.Intn(len(pool))]
	return p.es, p.lc
}

// Bytes returns a deterministic byte slice of length n, derived from the
// seed + label. Same (label, n) -> same bytes for one deployment.
func (i *Identity) Bytes(label string, n int) []byte {
	r := i.deterministicRand(label)
	buf := make([]byte, n)
	_, _ = r.Read(buf)
	return buf
}

// Uint32 returns a deterministic uint32 derived from the seed + label.
func (i *Identity) Uint32(label string) uint32 {
	r := i.deterministicRand(label)
	return r.Uint32()
}

// SerialNumber returns a stable but random-looking 32-bit serial for the
// fake EtherNet/IP / SMB device id.
func (i *Identity) SerialNumber() uint32 {
	// Deterministic per deployment (stable device id), but avoids
	// trivially-spottable values like 0x00000000 by forcing a high bit.
	return i.Uint32("device-serial") | 0x10000000
}

// MAC returns a stable 48-bit MAC address derived from the deployment_id.
// The locally-administered bit (0x02) is set on the first byte and the
// multicast bit (0x01) is cleared so the address is valid as a unicast
// MAC on the same L2 segment. Used by the honeynet ARP responder so each
// virtual host advertises a distinct hardware address.
func (i *Identity) MAC() [6]byte {
	b := i.Bytes("mac", 6)
	var out [6]byte
	copy(out[:], b)
	out[0] = (out[0] | 0x02) & 0xFE // locally-administered, unicast
	return out
}

// MACWithOUI returns a MAC whose first 3 bytes are the supplied
// vendor OUI and last 3 bytes are derived from the identity. This is
// the path used when an archetype pins a vendor OUI (Moxa, Siemens):
// every virtual host of that archetype gets a unique-but-vendor-
// shaped MAC so an arp-scan reports a believable population.
func (i *Identity) MACWithOUI(oui [3]byte) [6]byte {
	b := i.Bytes("mac-tail", 3)
	var out [6]byte
	out[0], out[1], out[2] = oui[0], oui[1], oui[2]
	copy(out[3:], b)
	return out
}
