package handler

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	xssh "golang.org/x/crypto/ssh"

	"github.com/rom/tarpit-honeypot/internal/archetype"
	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/identity"
	"github.com/rom/tarpit-honeypot/internal/jitter"
	"github.com/rom/tarpit-honeypot/internal/safe"
	"github.com/rom/tarpit-honeypot/internal/safego"
	"github.com/rom/tarpit-honeypot/internal/shell"
)

// sshInteractive is the post-login engagement variant of the SSH
// handler. Where the regular "ssh" handler does a banner-grab + HASSH
// fingerprint and then closes, this one runs a full crypto/ssh server,
// captures every password / pubkey attempt, and on the third
// credential attempt accepts and hands the session channel to the
// shell package for command-level TTP capture.
//
// Trade-offs:
//   - The crypto/ssh server uses an ed25519 host key persisted under
//     <data_dir>/tls/ssh_host_ed25519_key so the host-key fingerprint
//     is stable across restarts (a scanner that re-touches us doesn't
//     see a "key changed" warning).
//   - The banner is the archetype's SSH banner (or the identity-based
//     variant pool) — same source-of-truth as the banner-grab handler.
//   - The auth callback always returns failure on attempts 1..2 and
//     "ok" on attempt 3 so we capture multiple credential pairs
//     instead of accepting the first thing offered.
//   - Total session is bounded by shell.MaxCommands + shell.IdleTimeout
//     in the shell package. We add a hard SessionTimeout on top so
//     a stalled crypto/ssh dial can't pin a worker.
type sshInteractive struct {
	id   *identity.Identity
	jit  *jitter.Jitterer
	arch *archetype.Profile
	dir  string

	hostKeyOnce sync.Once
	hostKey     xssh.Signer
	hostKeyErr  error
}

func (s *sshInteractive) Name() string { return "ssh_interactive" }

// SessionTimeout caps the whole engagement (handshake + auth + shell)
// in wall-clock terms. shell.IdleTimeout / shell.MaxCommands cap the
// interactive phase; this is a defense-in-depth ceiling.
const SessionTimeout = 5 * time.Minute

// acceptAuthAfter is the credential-attempt index that we start
// accepting. Attempts before this index always fail (so we keep
// collecting passwords); attempts at or beyond it succeed (so we
// drop into the shell and capture TTPs).
const acceptAuthAfter = 3

func (s *sshInteractive) Handle(ctx context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	withTimeout(conn, SessionTimeout)
	s.jit.Sleep(ctx)

	signer, err := s.loadHostKey()
	if err != nil {
		return Result{Meta: map[string]any{"host_key_err": err.Error()}}, nil
	}

	res := Result{Meta: map[string]any{}}
	banner := s.bannerString()
	res.BannerSent = banner

	var (
		authMu       sync.Mutex
		authAttempts []map[string]any
		acceptedUser string
		clientID     string
	)

	sshCfg := &xssh.ServerConfig{
		ServerVersion: trimCRLF(banner),
		MaxAuthTries:  6,
		PasswordCallback: func(c xssh.ConnMetadata, pass []byte) (*xssh.Permissions, error) {
			authMu.Lock()
			defer authMu.Unlock()
			authAttempts = append(authAttempts, map[string]any{
				"method":   "password",
				"user":     safe.SanitizeForLog(c.User()),
				"password": safe.SanitizeForLog(string(pass)),
				"client":   safe.SanitizeForLog(string(c.ClientVersion())),
			})
			clientID = string(c.ClientVersion())
			if len(authAttempts) >= acceptAuthAfter {
				acceptedUser = c.User()
				return &xssh.Permissions{}, nil
			}
			return nil, errors.New("authentication failed")
		},
		PublicKeyCallback: func(c xssh.ConnMetadata, key xssh.PublicKey) (*xssh.Permissions, error) {
			authMu.Lock()
			defer authMu.Unlock()
			authAttempts = append(authAttempts, map[string]any{
				"method":        "publickey",
				"user":          safe.SanitizeForLog(c.User()),
				"key_type":      key.Type(),
				"key_fp_sha256": xssh.FingerprintSHA256(key),
				"client":        safe.SanitizeForLog(string(c.ClientVersion())),
			})
			// Pubkey never works on this honeypot; force them to
			// fall back to password.
			return nil, errors.New("publickey rejected")
		},
		BannerCallback: func(c xssh.ConnMetadata) string {
			return ""
		},
	}
	sshCfg.AddHostKey(signer)

	srvConn, channels, requests, err := xssh.NewServerConn(conn, sshCfg)
	authMu.Lock()
	res.Meta["auth_attempts"] = authAttempts
	res.Meta["client_id"] = safe.SanitizeForLog(clientID)
	if acceptedUser != "" {
		res.Meta["accepted_user"] = safe.SanitizeForLog(acceptedUser)
	}
	authMu.Unlock()
	if err != nil {
		// Failed handshake / auth — capture is already in meta.
		return res, nil
	}
	defer srvConn.Close()

	// Discard global requests (keepalives, tcpip-forward). Wrapped in
	// safego.Run so a panic in crypto/ssh request parsing — possible
	// with a malformed payload from a hostile client — doesn't bring
	// down the whole sensor process.
	safego.Run("ssh_interactive.discard_requests", func() {
		xssh.DiscardRequests(requests)
	})

	for newChan := range channels {
		if newChan.ChannelType() != "session" {
			_ = newChan.Reject(xssh.UnknownChannelType, "unknown channel type")
			continue
		}
		ch, chReqs, err := newChan.Accept()
		if err != nil {
			continue
		}
		s.runSession(ctx, ch, chReqs, &res)
		// Only run one session per engagement; clean up.
		_ = ch.Close()
		break
	}
	return res, nil
}

// runSession handles one xssh.Channel: walks the session-channel
// requests (pty-req / env / shell / exec / window-change), then hands
// the duplex stream to shell.Run for the command-level engagement.
func (s *sshInteractive) runSession(ctx context.Context, ch xssh.Channel, reqs <-chan *xssh.Request, res *Result) {
	gotShell := make(chan struct{}, 1)
	// Same panic-isolation rationale as the global-requests path:
	// session-channel requests (pty-req / env / exec / subsystem)
	// carry attacker-supplied payloads we don't fully validate.
	safego.Run("ssh_interactive.session_reqs", func() {
		for req := range reqs {
			switch req.Type {
			case "pty-req":
				if req.WantReply {
					_ = req.Reply(true, nil)
				}
			case "shell":
				if req.WantReply {
					_ = req.Reply(true, nil)
				}
				select {
				case gotShell <- struct{}{}:
				default:
				}
			case "exec":
				// Non-interactive `ssh host CMD` — capture the
				// command line and respond with our shell's
				// canned response, then close.
				if len(req.Payload) >= 4 {
					cmdLen := int(req.Payload[0])<<24 | int(req.Payload[1])<<16 | int(req.Payload[2])<<8 | int(req.Payload[3])
					if cmdLen > 0 && cmdLen <= len(req.Payload)-4 {
						cmd := string(req.Payload[4 : 4+cmdLen])
						res.Meta["exec_command"] = safe.SanitizeForLog(cmd)
						// scan anomalies on the exec line.
						for _, a := range shell.ScanAnomalies(cmd) {
							flagAnomaly(res, a)
						}
					}
				}
				if req.WantReply {
					_ = req.Reply(true, nil)
				}
				_, _ = ch.Write([]byte("Permission denied\r\n"))
				_, _ = ch.SendRequest("exit-status", false, []byte{0, 0, 0, 1})
				return
			case "env", "window-change", "subsystem":
				if req.WantReply {
					_ = req.Reply(true, nil)
				}
			default:
				if req.WantReply {
					_ = req.Reply(false, nil)
				}
			}
		}
	})

	// Wait for the "shell" request before driving the shell loop.
	select {
	case <-gotShell:
	case <-time.After(10 * time.Second):
		return
	case <-ctx.Done():
		return
	}

	// "Last login" greeting line — what a real distro shows.
	_, _ = ch.Write([]byte("Last login: Mon May 19 13:01:22 from 10.0.0.5\r\n"))

	captured := shell.Run(ctx, ch, ch, s.arch)
	if len(captured.Commands) > 0 {
		res.Meta["shell_commands"] = captured.Commands
	}
	for _, a := range captured.Anomalies {
		flagAnomaly(res, a)
	}
	// Send exit-status 0 so OpenSSH client sees a clean session end.
	_, _ = ch.SendRequest("exit-status", false, []byte{0, 0, 0, 0})
}

// bannerString returns the SSH-2.0-... identification line for this
// archetype, including a trailing CRLF as the SSH protocol expects.
// crypto/ssh will use the leading "SSH-2.0-<x>" portion as the
// ServerVersion; the CRLF is added by the library.
func (s *sshInteractive) bannerString() string {
	switch {
	case s.arch != nil && s.arch.SSHBanner() != "":
		return s.arch.SSHBanner()
	case s.id != nil:
		return s.id.SSHBannerVariant()
	}
	return "SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u1"
}

// loadHostKey reads or generates the persistent ed25519 host key. The
// key is stored under <data_dir>/tls/ssh_host_ed25519_key in
// PEM-encoded OpenSSH-private form. Once cached on first call the
// signer is reused for every subsequent session.
func (s *sshInteractive) loadHostKey() (xssh.Signer, error) {
	s.hostKeyOnce.Do(func() {
		s.hostKey, s.hostKeyErr = s.loadOrGenerateHostKey()
	})
	return s.hostKey, s.hostKeyErr
}

func (s *sshInteractive) loadOrGenerateHostKey() (xssh.Signer, error) {
	if s.dir == "" {
		// No data_dir: ephemeral host key (rebuilds on every
		// listener restart). Acceptable for sensor-rebuild-anyway
		// scenarios; logs a warning is the caller's job.
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		return xssh.NewSignerFromKey(priv)
	}
	if err := os.MkdirAll(s.dir, 0o750); err != nil {
		return nil, fmt.Errorf("mkdir tls dir: %w", err)
	}
	path := filepath.Join(s.dir, "ssh_host_ed25519_key")
	if pemBytes, err := os.ReadFile(path); err == nil {
		block, _ := pem.Decode(pemBytes)
		if block != nil {
			signer, err := xssh.ParsePrivateKey(pemBytes)
			if err == nil {
				return signer, nil
			}
		}
	}
	// Generate fresh.
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	signer, err := xssh.NewSignerFromKey(priv)
	if err != nil {
		return nil, err
	}
	// Persist as OpenSSH PEM so a `ssh-keygen -l -f <path>` works.
	out, err := marshalEd25519Private(priv)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, out, 0o600); err != nil {
		// Persistence failed (read-only fs, quota, permission…). The
		// generated signer is still usable for this session but the
		// fingerprint won't be stable across restarts — a re-scan
		// of the honeypot will see a "key changed" warning. Log the
		// reason so the operator can fix the underlying issue.
		slog.Warn("ssh_interactive: host key persistence failed; running ephemeral",
			"path", path, "err", err)
	}
	return signer, nil
}

// marshalEd25519Private re-emits the key in the OpenSSH PEM format
// crypto/ssh understands via xssh.ParsePrivateKey on read. We use
// MarshalPrivateKey from x/crypto/ssh (available since Go 1.20-era
// versions) — falls back to manual PEM emission otherwise.
func marshalEd25519Private(priv ed25519.PrivateKey) ([]byte, error) {
	pemBlock, err := xssh.MarshalPrivateKey(priv, "")
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(pemBlock), nil
}

func trimCRLF(s string) string {
	for len(s) > 0 && (s[len(s)-1] == '\r' || s[len(s)-1] == '\n') {
		s = s[:len(s)-1]
	}
	return s
}
