package handler

import (
	"bufio"
	"context"
	"encoding/binary"
	"io"
	"net"
	"strings"

	"github.com/rom/tarpit-honeypot/internal/archetype"
	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/fingerprint"
	"github.com/rom/tarpit-honeypot/internal/identity"
	"github.com/rom/tarpit-honeypot/internal/jitter"
	"github.com/rom/tarpit-honeypot/internal/toolfp"
)

type ssh struct {
	id     *identity.Identity
	jit    *jitter.Jitterer
	arch   *archetype.Profile
	vuln   bool
	kexExt bool // capture beyond KEXINIT/HASSH (interaction.ssh_kex_depth: extended_experimental)
}

func (s *ssh) Name() string { return "ssh" }

// SSH identification string per RFC 4253 §4.2. We send a believable banner
// immediately followed by our own SSH_MSG_KEXINIT (so the server HASSH is
// realistic and version-consistent), read the client's identification line,
// then read one client SSH_MSG_KEXINIT packet to compute the client HASSH
// fingerprint, and drop the connection.
//
// The banner picks from a deployment-unique variant pool when an Identity
// is supplied — two sensors with different deployment_id values present
// distinct SSH versions to a scanner, so they don't cluster on the same
// JA3/HASSH-style banner-grab fingerprint.
func (s *ssh) Handle(ctx context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	withTimeout(conn, cfg.ReadTimeout)
	s.jit.Sleep(ctx)
	banner := cfg.Banner
	if banner == "" {
		switch {
		case s.vuln && s.arch != nil && s.arch.VulnBanner("ssh") != "":
			banner = s.arch.VulnBanner("ssh") + "\r\n"
		case s.arch != nil && s.arch.SSHBanner() != "":
			banner = s.arch.SSHBanner() + "\r\n"
		case s.id != nil:
			banner = s.id.SSHBannerVariant() + "\r\n"
		default:
			banner = "SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u1\r\n"
		}
	}
	res := Result{BannerSent: banner, Meta: map[string]any{}}
	// Send the banner immediately followed by our own SSH_MSG_KEXINIT,
	// exactly as a real OpenSSH server pipelines them. Without this a
	// scanner computing the *server* HASSH sees "banner then silence",
	// which is a honeypot tell; with it, the advertised algorithm set is
	// consistent with the version banner (derived from it). One write
	// keeps the net.Pipe path (and real clients) from stalling.
	out := []byte(banner)
	if strings.HasPrefix(banner, "SSH-") {
		kexPayload := buildKEXINITPayload(sshAlgosForBanner(banner))
		out = append(out, frameSSHPacket(kexPayload)...)
		if _, sum := fingerprint.HASSH(kexPayload); sum != "" {
			res.Meta["hassh_server"] = sum
		}
	}
	if _, err := conn.Write(out); err != nil {
		res.Meta["write_err"] = err.Error()
		return res, nil
	}
	br := bufio.NewReader(conn)
	// RFC 4253 §4.2 caps the identification string at 255 bytes; read a
	// bounded line (not ReadString, which would buffer an attacker's
	// newline-less stream up to the read deadline) so a peer can't force a
	// large allocation. Anything longer is flagged overlong below.
	line, err := readFTPLine(br, 512)
	if err == nil && line != "" {
		res.Payload = []byte(line)
		res.Meta["client_id"] = line
		// SSH identification strings are ASCII per RFC 4253 §4.2 —
		// non-printable bytes mean someone's fuzzing or running a
		// non-SSH scanner against the port.
		if hasNonPrintable(line) {
			flagAnomaly(&res, "ssh-id-non-printable")
		}
		if len(line) > 255 {
			flagAnomaly(&res, "ssh-id-overlong")
		}
		if !strings.HasPrefix(line, "SSH-") {
			flagAnomaly(&res, "ssh-id-not-ssh")
		}
		// Identify the SSH client/scanner from its banner (libssh→hydra,
		// paramiko, zgrab, Go, PuTTY, ...). The banner is clear-text pre-KEX.
		if tools := toolfp.IdentifySSH(line); len(tools) > 0 {
			res.Meta["tools"] = tools
			flagAnomaly(&res, "tool:"+tools[0])
			// The SSH client ID is sent in clear pre-KEX, so a banner match
			// is a high-confidence self-identification.
			res.Meta["tool_confidence"] = toolfp.ConfHigh
			res.Meta["tool_confidence_label"] = toolfp.ConfidenceLabel(toolfp.ConfHigh)
		}
		// CVE-2016-0777/0778: a vulnerable OpenSSH client (roaming default-on)
		// connecting to us is the precondition for the roaming key-leak.
		flagSSHRoaming(&res, line)
	} else if err != nil {
		res.Meta["read_err"] = err.Error()
	}

	// Try to read one binary-packet (the client's SSH_MSG_KEXINIT) for the
	// client HASSH fingerprint, then drop the connection (we never carry
	// the key exchange through).
	//
	// In extended mode (interaction.ssh_kex_depth: extended_experimental) we
	// read the full KEXINIT packet, compute HASSH from it, capture the full
	// algorithm breakdown + negotiated KEX, and read the client's first
	// key-exchange message (the ephemeral public value). Otherwise we take
	// the cheap HASSH-only path.
	if s.kexExt {
		if payload, ok := readSSHPacket(br); ok {
			if raw, sum := fingerprint.HASSH(payload); raw != "" {
				res.Meta["hassh"] = sum
				res.Meta["hassh_algorithms"] = raw
			}
			captureExtendedKex(br, payload, sshAlgosForBanner(banner).kex, &res)
		}
	} else if hashRaw, hashSum, ok := readHASSH(br); ok {
		res.Meta["hassh"] = hashSum
		res.Meta["hassh_algorithms"] = hashRaw
	}
	return res, nil
}

// readHASSH reads one SSH binary packet from br (RFC 4253 §6), and feeds
// the payload to fingerprint.HASSH. Returns ("","",false) on any failure.
func readHASSH(br *bufio.Reader) (string, string, bool) {
	hdr, err := peekN(br, 5)
	if err != nil {
		return "", "", false
	}
	pktLen := binary.BigEndian.Uint32(hdr[0:4])
	if pktLen < 1 || pktLen > 65535 {
		return "", "", false
	}
	full := make([]byte, 4+pktLen)
	if _, err := io.ReadFull(br, full); err != nil {
		return "", "", false
	}
	raw, sum := fingerprint.HASSH(full)
	return raw, sum, raw != ""
}

func peekN(br *bufio.Reader, n int) ([]byte, error) {
	b, err := br.Peek(n)
	if err != nil {
		return nil, err
	}
	out := make([]byte, n)
	copy(out, b)
	return out, nil
}
