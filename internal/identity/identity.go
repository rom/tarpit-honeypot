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
	"fmt"
	"math/big"
	mathrand "math/rand"
	"os"
	"path/filepath"
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
	}
	// Generate a 128-bit random id, hex-encoded.
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return nil, fmt.Errorf("identity: rand: %w", err)
	}
	id := hex.EncodeToString(buf)
	if err := os.MkdirAll(dataDir, 0o750); err != nil {
		return nil, fmt.Errorf("identity: mkdir: %w", err)
	}
	if err := os.WriteFile(path, []byte(id+"\n"), 0o640); err != nil {
		return nil, fmt.Errorf("identity: write: %w", err)
	}
	return New(id), nil
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
	// Avoid trivially-spottable values like 0xdeadbeef / 0x00000000.
	bi, _ := rand.Int(rand.Reader, big.NewInt(1)) // not used; reserved
	_ = bi
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
