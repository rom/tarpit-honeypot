package handler

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	xssh "golang.org/x/crypto/ssh"

	"github.com/rom/tarpit-honeypot/internal/archetype"
	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/identity"
	"github.com/rom/tarpit-honeypot/internal/jitter"
	"github.com/rom/tarpit-honeypot/internal/safe"
	"github.com/rom/tarpit-honeypot/internal/safego"
	"github.com/rom/tarpit-honeypot/internal/sessionrec"
	"github.com/rom/tarpit-honeypot/internal/shell"
	"github.com/rom/tarpit-honeypot/internal/toolfp"
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
	id      *identity.Identity
	jit     *jitter.Jitterer
	arch    *archetype.Profile
	dir     string // TLS/host-key dir (<data_dir>/tls)
	dataDir string // sensor data dir root (for the persistent shell overlay)
	rec     *sessionrec.Store
	// vuln enables vulnerability *emulation*: when set, the handler accepts the
	// SSH auth-bypass signatures (Alpine blank-root CVE-2019-5021, the *sshole
	// 257–1024 byte musl password bypass) on the first matching attempt so the
	// attacker is trapped in the (fake) shell. Detection of these signatures is
	// always on regardless; vuln only controls whether the trap "succeeds".
	vuln bool

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
				"pass_len": len(pass),
				"client":   safe.SanitizeForLog(string(c.ClientVersion())),
			})
			clientID = string(c.ClientVersion())
			// Vulnerability trap: with vuln emulation on, present as exploitable
			// to the SSH auth-bypass signatures so the attacker is trapped in the
			// fake shell. The *sshole bypass accepts any 257–1024 byte password on
			// a locked account; Alpine CVE-2019-5021 accepts a blank password for
			// a privileged account. The shell runs nothing real — this grants no
			// actual access, it just makes the honeypot look vulnerable.
			if s.vuln && sshBypassAccept(c.User(), len(pass)) {
				acceptedUser = c.User()
				return &xssh.Permissions{}, nil
			}
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
	// Surface the offered SSH public-key fingerprints at the top level too
	// ("type:SHA256:…") so the IOC extractor can index them — a pubkey an
	// actor reuses across hosts is a strong attribution indicator.
	var pubkeyFPs []string
	for _, a := range authAttempts {
		if fp, _ := a["key_fp_sha256"].(string); fp != "" {
			kt, _ := a["key_type"].(string)
			pubkeyFPs = appendUnique(pubkeyFPs, kt+":"+fp)
		}
	}
	if len(pubkeyFPs) > 0 {
		res.Meta["ssh_pubkey_fps"] = pubkeyFPs
	}
	res.Meta["client_id"] = safe.SanitizeForLog(clientID)
	if acceptedUser != "" {
		res.Meta["accepted_user"] = safe.SanitizeForLog(acceptedUser)
	}
	// Identify the tool/library from the client banner — the banner-grab "ssh"
	// handler does this, but this is the variant that actually captures
	// credentials, so without it brute-force credential testers (hydra/medusa/
	// ncrack/patator on libssh/paramiko, …) never reach the "top tools" view.
	if clientID != "" {
		if tools := toolfp.IdentifySSH(clientID); len(tools) > 0 {
			res.Meta["tools"] = tools
			for _, t := range tools {
				flagAnomaly(&res, "tool:"+t)
			}
			res.Meta["tool_confidence"] = toolfp.ConfHigh
			res.Meta["tool_confidence_label"] = toolfp.ConfidenceLabel(toolfp.ConfHigh)
		}
		flagSSHRoaming(&res, clientID)
	}
	// SSH auth-bypass / enumeration signatures (always on, even when the
	// handshake ultimately failed): oversized (>256) passwords, the *sshole
	// musl bypass, Alpine blank-root CVE-2019-5021, and CVE-2016-6210 giant-
	// password user enumeration.
	scanSSHAuthThreats(&res, authAttempts)
	authMu.Unlock()
	if err != nil {
		// Failed handshake / auth — capture is already in meta.
		return res, nil
	}
	defer srvConn.Close()

	// Service global requests: reject them like a locked-down server, but flag a
	// remote port-forward (tcpip-forward) — a tunneling/pivot intent. Wrapped in
	// safego.Run so a panic in crypto/ssh request parsing — possible with a
	// malformed payload from a hostile client — doesn't bring down the sensor.
	var remoteForward atomic.Bool
	safego.Run("ssh_interactive.global_requests", func() {
		for req := range requests {
			if req.Type == "tcpip-forward" || req.Type == "cancel-tcpip-forward" {
				remoteForward.Store(true)
			}
			if req.WantReply {
				_ = req.Reply(false, nil)
			}
		}
	})

	for newChan := range channels {
		// A direct-tcpip / forwarded-tcpip channel is local/dynamic port
		// forwarding — a tunneling / pivot attempt through the honeypot.
		if ct := newChan.ChannelType(); ct == "direct-tcpip" || ct == "forwarded-tcpip" {
			flagAnomaly(&res, "ssh-direct-tcpip")
			res.Meta["intent"] = "SSH " + ct + " channel — port-forward tunneling / pivot"
			_ = newChan.Reject(xssh.Prohibited, "forwarding not permitted")
			continue
		}
		if newChan.ChannelType() != "session" {
			_ = newChan.Reject(xssh.UnknownChannelType, "unknown channel type")
			continue
		}
		ch, chReqs, err := newChan.Accept()
		if err != nil {
			continue
		}
		s.runSession(ctx, ch, chReqs, &res, hostFromAddr(conn.RemoteAddr()))
		// Only run one session per engagement; clean up.
		_ = ch.Close()
		break
	}
	if remoteForward.Load() {
		flagAnomaly(&res, "ssh-remote-forward")
		setIfEmpty(res.Meta, "intent", "SSH remote port-forward (tcpip-forward) — tunneling / pivot")
	}
	// CVE-2016-0777: after the engagement, set the roaming trap for a
	// vulnerable client (best-effort, bounded). See offerSSHRoaming.
	offerSSHRoaming(srvConn, clientID, &res)
	return res, nil
}

// offerSSHRoaming sends the OpenSSH "roaming@openssh.com" global request to a
// vulnerable client and records whether it was accepted. A vulnerable client
// (OpenSSH 5.4–7.1) enables roaming on receipt — the server-side precondition
// for the CVE-2016-0777 memory/key disclosure. It runs after the session is
// over (so it never delays the interactive engagement) and is bounded by a
// short timeout so a silent client can't pin the worker. The actual private
// key arrives only via the roaming *resume* exchange, which crypto/ssh does
// not implement; this records the trap + the client's reaction.
func offerSSHRoaming(conn *xssh.ServerConn, clientID string, res *Result) {
	if conn == nil {
		return
	}
	if _, vuln := openSSHRoamingVulnerable(clientID); !vuln {
		return
	}
	done := make(chan bool, 1)
	safego.Run("ssh_interactive.roaming_offer", func() {
		ok, _, err := conn.SendRequest("roaming@openssh.com", true, nil)
		done <- err == nil && ok
	})
	accepted := false
	select {
	case accepted = <-done:
	case <-time.After(3 * time.Second):
	}
	res.Meta["ssh_roaming_offered"] = true
	res.Meta["ssh_roaming_client_accepted"] = accepted
	flagAnomaly(res, "ssh-roaming-offered")
}

// runSession handles one xssh.Channel: walks the session-channel
// requests (pty-req / env / shell / exec / window-change), then hands
// the duplex stream to shell.Run for the command-level engagement.
func (s *sshInteractive) runSession(ctx context.Context, ch xssh.Channel, reqs <-chan *xssh.Request, res *Result, peer string) {
	gotShell := make(chan struct{}, 1)
	done := make(chan struct{}, 1) // exec / sftp / scp handled — session is over
	finish := func() {
		select {
		case done <- struct{}{}:
		default:
		}
	}
	// Same panic-isolation rationale as the global-requests path:
	// session-channel requests (pty-req / env / exec / subsystem)
	// carry attacker-supplied payloads we don't fully validate.
	safego.Run("ssh_interactive.session_reqs", func() {
		for req := range reqs {
			switch req.Type {
			case "x11-req":
				// X11 forwarding request — GUI tunneling / pivot intent.
				flagAnomaly(res, "ssh-x11-forward")
				setIfEmpty(res.Meta, "intent", "SSH X11 forwarding requested — tunneling / pivot")
				if req.WantReply {
					_ = req.Reply(true, nil)
				}
			case "auth-agent-req@openssh.com":
				// Agent forwarding — credential-theft / lateral-movement primitive.
				flagAnomaly(res, "ssh-agent-forward")
				setIfEmpty(res.Meta, "intent", "SSH agent forwarding requested — credential theft / lateral movement")
				if req.WantReply {
					_ = req.Reply(true, nil)
				}
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
				// Non-interactive `ssh host CMD` — capture the command line.
				// scp invokes the server side this way (`scp -t`/`scp -f`); we
				// emulate the start of the transfer to fingerprint the attempt.
				cmd := sshReqString(req.Payload)
				res.Meta["exec_command"] = safe.SanitizeForLog(cmd)
				for _, a := range shell.ScanAnomalies(cmd) {
					flagAnomaly(res, a)
				}
				if req.WantReply {
					_ = req.Reply(true, nil)
				}
				if isSCPCommand(cmd) {
					serveSCPBeginning(ch, res, cmd)
				} else {
					_, _ = ch.Write([]byte("Permission denied\r\n"))
				}
				_, _ = ch.SendRequest("exit-status", false, []byte{0, 0, 0, 1})
				finish()
				return
			case "subsystem":
				// The sftp subsystem: emulate the SFTP start (INIT->VERSION,
				// then record + deny) so the client reveals which paths it
				// probes; other subsystems are refused.
				name := sshReqString(req.Payload)
				if name == "sftp" {
					if req.WantReply {
						_ = req.Reply(true, nil)
					}
					serveSFTPBeginning(ch, res)
					_, _ = ch.SendRequest("exit-status", false, []byte{0, 0, 0, 0})
				} else {
					res.Meta["ssh_subsystem"] = safe.SanitizeForLog(name)
					if req.WantReply {
						_ = req.Reply(false, nil)
					}
				}
				finish()
				return
			case "env":
				// An env value beginning with "() {" is a Bash function
				// definition — Shellshock (CVE-2014-6271) pushed through
				// AcceptEnv to a CGI/forced-command shell.
				if name, val, ok := sshEnvPair(req.Payload); ok {
					if strings.HasPrefix(strings.TrimSpace(val), "() {") {
						flagAnomaly(res, "ssh-env-shellshock")
						res.CVEHits = appendUnique(res.CVEHits, "CVE-2014-6271")
						flagAnomaly(res, "cve:CVE-2014-6271")
						res.Meta["intent"] = "SSH env Shellshock via AcceptEnv (" + safe.SanitizeForLog(name) + ") — CVE-2014-6271"
					}
				}
				if req.WantReply {
					_ = req.Reply(true, nil)
				}
			case "window-change":
				if req.WantReply {
					_ = req.Reply(true, nil)
				}
			default:
				if req.WantReply {
					_ = req.Reply(false, nil)
				}
			}
		}
		finish()
	})

	// Wait for the "shell" request before driving the shell loop; a terminal
	// exec / sftp / scp request ends the session via done instead.
	select {
	case <-gotShell:
	case <-done:
		return
	case <-time.After(10 * time.Second):
		return
	case <-ctx.Done():
		return
	}

	// "Last login" greeting line — what a real distro shows.
	_, _ = ch.Write([]byte("Last login: Mon May 19 13:01:22 from 10.0.0.5\r\n"))

	var inR io.Reader = ch
	var outW io.Writer = ch
	if s.rec != nil {
		if rc, name, err := s.rec.Begin(peer); err == nil {
			defer rc.Close()
			inR, outW = rc.Reader(ch), rc.Writer(ch)
			res.Meta["session_cast"] = name
		}
	}
	// Persistent per-attacker overlay filesystem: load what this source changed
	// in earlier sessions, run the shell against it, and save it back — so a
	// dropped payload / created file is still there on reconnect and the dropper
	// URL is preserved across sessions. Keyed by source IP under <data_dir>.
	vfs := shell.LoadFS(s.dataDir, peer, "/root")
	captured := shell.RunWithFS(ctx, inR, outW, s.arch, vfs)
	if err := shell.SaveFS(s.dataDir, peer, vfs); err != nil {
		slog.Debug("ssh_interactive: persist shell fs", "err", err)
	}
	if n := len(vfs.Nodes); n > 0 {
		res.Meta["shell_fs_files"] = n
	}
	if len(vfs.Downloads) > 0 {
		res.Meta["shell_downloads"] = vfs.Downloads
		flagAnomaly(res, "shell-payload-download")
	}
	if len(captured.Commands) > 0 {
		res.Meta["shell_commands"] = captured.Commands
	}
	if len(captured.HarvestedURLs) > 0 {
		// Surfaced for the sensor's IOC pipeline (download / C2 hosts).
		res.Meta["harvested_urls"] = captured.HarvestedURLs
	}
	if len(captured.ServedLootTokens) > 0 {
		// The per-deployment canary woven into loot the attacker read. The
		// sensor records it (servedTokenKeys) so a later replay of the secret
		// fires a critical canary:token_used. Per-deployment, so all entries are
		// the same value — surface one.
		res.Meta["loot_token"] = captured.ServedLootTokens[0]
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
