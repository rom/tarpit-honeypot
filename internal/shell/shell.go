// Package shell implements a low-interaction post-login command-line
// engagement layer. After a fake "login accepted", SSH and Telnet
// handlers hand the connection to shell.Run, which:
//
//   - Emits the archetype's CLI prompt.
//   - Reads commands one line at a time, splits into argv.
//   - Looks up a per-archetype response and writes it back.
//   - Records every command + any anomaly markers (reverse shells,
//     /etc/shadow reads, authorized_keys writes, wget/curl attempts,
//     ./scripts and base64-encoded payloads) so the SIEM gets a
//     full TTP trail instead of "ssh banner + close".
//
// The shell never executes anything real. Everything is canned text
// and a string-keyed lookup table; the engagement is bounded by
// MaxCommands and MaxBytesPerCommand so a fuzzer can't burn
// resources walking us indefinitely.
package shell

import (
	"bufio"
	"context"
	"io"
	"strings"
	"time"

	"github.com/rom/tarpit-honeypot/internal/archetype"
	"github.com/rom/tarpit-honeypot/internal/safe"
)

// MaxCommands caps the engagement length. After N commands we send a
// "Connection closed by foreign host" line and exit, which is what a
// real machine does on idle-timeout / max-auth-failures / sshd
// MaxSessions.
const MaxCommands = 32

// MaxBytesPerCommand is the per-line read cap. Anything longer is
// silently truncated — the attacker sees a fragmented response, the
// log records the truncation, and we don't accept arbitrarily-large
// strings in this code path.
const MaxBytesPerCommand = 8192

// IdleTimeout is the max wait between commands. Past it we drop the
// session so a stuck connection can't hold a worker forever.
const IdleTimeout = 60 * time.Second

// Captured is what the shell hands back to the caller — usually the
// SSH or Telnet handler — so it can append everything to its Result
// meta + anomalies list.
type Captured struct {
	Commands  []string // every line the attacker typed, truncated at MaxBytesPerCommand
	Anomalies []string // markers like "shell-reverse-shell", "shell-shadow-read"
	// HarvestedURLs are http(s) URLs seen in the attacker's commands (wget /
	// curl ingress-tool-transfer, pipe-to-shell, exfil targets). Surfaced to
	// the handler as meta so the sensor's IOC pipeline ingests the download /
	// C2 hosts.
	HarvestedURLs []string
	// ServedLootTokens are the per-deployment canary token values woven into any
	// planted loot credential file the attacker read this session. Surfaced to
	// the handler as meta["loot_token"] so the sensor records them in the
	// honey-credential reuse tracker: a later replay of the captured secret
	// against any login-bearing service then fires a critical canary:token_used.
	ServedLootTokens []string
}

// Run drives the engagement. Returns when the attacker types exit/quit,
// when EOF arrives, when MaxCommands is reached, when IdleTimeout
// elapses, or when ctx is cancelled.
//
// arch may be nil — in that case we use a plain "$ " prompt and the
// POSIX default response set.
func Run(ctx context.Context, r io.Reader, w io.Writer, arch *archetype.Profile) Captured {
	cap := Captured{}
	prompt := promptFor(arch)
	responses := responseTable(arch)
	fold := foldCommands(arch)

	br := bufio.NewReader(r)
	deadline := time.NewTimer(IdleTimeout)
	defer deadline.Stop()

	for i := 0; i < MaxCommands; i++ {
		if _, err := io.WriteString(w, prompt); err != nil {
			return cap
		}
		line, err := readBoundedLine(br, MaxBytesPerCommand)
		if err != nil {
			return cap
		}
		// Drop trailing CR/LF — telnet often sends CR-LF, ssh just LF.
		line = strings.TrimRight(line, "\r\n")
		// Empty line is a normal prompt re-render, like a real shell.
		if line == "" {
			continue
		}
		cap.Commands = append(cap.Commands, safe.SanitizeForLog(line))

		// Flag the line for malicious markers BEFORE looking up the
		// response so the log records "attacker tried wget" even
		// when our table doesn't recognize the exact command form.
		for _, a := range scanAnomalies(line) {
			cap.Anomalies = appendUnique(cap.Anomalies, a)
		}
		for _, u := range harvestURLs(line) {
			cap.HarvestedURLs = appendUnique(cap.HarvestedURLs, u)
		}
		// A read of a planted loot credential file served the per-deployment
		// canary — record it so the handler can surface it and the sensor can
		// track replays of the "stolen" secret.
		if lootReadLine(strings.ToLower(line)) {
			cap.ServedLootTokens = appendUnique(cap.ServedLootTokens, currentLootToken())
		}

		argv := splitArgv(line)
		if len(argv) == 0 {
			continue
		}
		cmd := argv[0]
		if fold {
			cmd = strings.ToLower(cmd)
		}

		if cmd == "exit" || cmd == "logout" || cmd == "quit" {
			_, _ = io.WriteString(w, "logout\r\n")
			return cap
		}

		resp := lookupResponse(responses, cmd, argv)
		if _, err := io.WriteString(w, resp); err != nil {
			return cap
		}

		// Re-arm the idle timer. We check ctx between iterations.
		if !deadline.Stop() {
			select {
			case <-deadline.C:
			default:
			}
		}
		deadline.Reset(IdleTimeout)
		select {
		case <-ctx.Done():
			return cap
		default:
		}
	}
	_, _ = io.WriteString(w, "\r\nConnection to host closed.\r\n")
	return cap
}

// OneShot evaluates a single command line against the archetype's canned
// response table and returns the output plus any TTP anomaly markers,
// without an interactive loop. Used by the fake web-shell HTTP behavior:
// an attacker's submitted command is scanned + answered with believable
// canned output, but is never executed.
func OneShot(arch *archetype.Profile, line string) (output string, anomalies []string) {
	line = strings.TrimRight(line, "\r\n")
	if line == "" {
		return "", nil
	}
	for _, a := range scanAnomalies(line) {
		anomalies = appendUnique(anomalies, a)
	}
	argv := splitArgv(line)
	if len(argv) == 0 {
		return "", anomalies
	}
	cmd := argv[0]
	if foldCommands(arch) {
		cmd = strings.ToLower(cmd)
	}
	return lookupResponse(responseTable(arch), cmd, argv), anomalies
}

// readBoundedLine reads up to max bytes or until '\n', whichever
// comes first. The returned string is the line as read (may include
// the terminating '\n'); when the buffer fills before '\n' we discard
// the remainder of the line so the next prompt is in sync.
func readBoundedLine(br *bufio.Reader, max int) (string, error) {
	var sb strings.Builder
	for sb.Len() < max {
		b, err := br.ReadByte()
		if err != nil {
			if sb.Len() > 0 {
				return sb.String(), nil
			}
			return "", err
		}
		sb.WriteByte(b)
		if b == '\n' {
			return sb.String(), nil
		}
	}
	// We hit the cap mid-line — drain to next '\n' so the next read
	// starts at a clean boundary.
	for {
		b, err := br.ReadByte()
		if err != nil || b == '\n' {
			break
		}
	}
	return sb.String(), nil
}

// promptFor returns the archetype's post-login prompt, or "$ " when
// no archetype is configured (the safest generic).
func promptFor(p *archetype.Profile) string {
	if p == nil || p.CLIPrompt() == "" {
		return "$ "
	}
	return p.CLIPrompt()
}

// splitArgv splits a single shell line into argv. Quoting is
// intentionally minimal — we don't run anything, we just need a
// reasonable "first token" + arg list for the response lookup.
// Double-quoted and single-quoted runs are honored (no escape inside
// single quotes; \" supported inside double quotes).
func splitArgv(line string) []string {
	var out []string
	var cur strings.Builder
	inSingle, inDouble := false, false
	flush := func() {
		if cur.Len() > 0 {
			out = append(out, cur.String())
			cur.Reset()
		}
	}
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case inSingle:
			if c == '\'' {
				inSingle = false
			} else {
				cur.WriteByte(c)
			}
		case inDouble:
			if c == '"' {
				inDouble = false
			} else if c == '\\' && i+1 < len(line) {
				cur.WriteByte(line[i+1])
				i++
			} else {
				cur.WriteByte(c)
			}
		case c == '\'':
			inSingle = true
		case c == '"':
			inDouble = true
		case c == ' ' || c == '\t':
			flush()
		default:
			cur.WriteByte(c)
		}
	}
	flush()
	return out
}

func appendUnique(list []string, item string) []string {
	for _, e := range list {
		if e == item {
			return list
		}
	}
	return append(list, item)
}
