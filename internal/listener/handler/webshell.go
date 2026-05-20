package handler

import (
	"net/url"
	"strings"

	"github.com/rom/tarpit-honeypot/internal/archetype"
	"github.com/rom/tarpit-honeypot/internal/safe"
	"github.com/rom/tarpit-honeypot/internal/shell"
)

// Fake web shells. Attackers spray requests for well-known web-shell
// filenames (c99 / r57 / wso / b374k / China Chopper) and, once they
// believe one is installed, drive it with a command parameter
// (?cmd=, POST cmd=, China Chopper's key=). We always DETECT these
// (flag + capture the command) and, when vuln emulation is enabled,
// actively SERVE a believable fake shell whose command output comes from
// the canned shell emulator — so the attacker reveals recon TTPs against
// a service that never executes anything.

// knownWebshellNames is the set of last-path-segment filenames that are
// almost exclusively web shells. Matching is case-insensitive.
var knownWebshellNames = map[string]bool{
	"c99.php": true, "r57.php": true, "wso.php": true, "b374k.php": true,
	"alfa.php": true, "shell.php": true, "cmd.php": true, "up.php": true,
	"webshell.php": true, "backdoor.php": true, "0day.php": true,
	"indoxploit.php": true, "marijuana.php": true, "mini.php": true,
	"adminer.php": true, "sym.php": true, "x.php": true, "1.php": true,
	"shell.jsp": true, "cmd.jsp": true, "shell.aspx": true, "cmd.aspx": true,
	"shell.asp": true, "tunnel.jsp": true, "sh.php": true, "p.php": true,
}

// webshellCmdParams are the parameter names common shells read the command
// from. China Chopper historically uses a short key; generic PHP shells
// use cmd/c/x/exec.
var webshellCmdParams = []string{
	"cmd", "c", "x", "exec", "command", "q", "e", "cmd0", "cmd1",
	"act", "run", "shell", "execute", "system",
}

// detectWebshell reports whether a request looks like web-shell activity
// and extracts the command, if any.
func detectWebshell(path string, body []byte, contentType string) (hit bool, cmd string) {
	rawPath, rawQuery := splitPathQuery(path)
	base := strings.ToLower(lastSegment(rawPath))
	if knownWebshellNames[base] {
		hit = true
	}
	// Command in the query string.
	if c := rawParam(rawQuery, webshellCmdParams); c != "" {
		cmd, hit = c, true
	}
	// Command in a urlencoded POST body.
	if cmd == "" && isFormBody(contentType) {
		if c := rawParam(string(body), webshellCmdParams); c != "" {
			cmd, hit = c, true
		}
	}
	return hit, cmd
}

// rawParam extracts the first matching parameter value from a urlencoded
// query/body. It splits only on '&' (not ';') because shell commands
// routinely contain ';' and would break url.ParseQuery, and best-effort
// URL-decodes the value.
func rawParam(raw string, keys []string) string {
	if raw == "" {
		return ""
	}
	for _, seg := range strings.Split(raw, "&") {
		eq := strings.IndexByte(seg, '=')
		if eq <= 0 {
			continue
		}
		k := seg[:eq]
		for _, want := range keys {
			if strings.EqualFold(k, want) {
				v, err := url.QueryUnescape(seg[eq+1:])
				if err != nil {
					v = seg[eq+1:]
				}
				return v
			}
		}
	}
	return ""
}

func splitPathQuery(p string) (path, query string) {
	if i := strings.IndexByte(p, '?'); i >= 0 {
		return p[:i], p[i+1:]
	}
	return p, ""
}

func lastSegment(p string) string {
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		return p[i+1:]
	}
	return p
}

// webshellPage renders the fake web-shell HTML for a (possibly empty)
// command + its canned output. cmdOut is already the emulator output.
func webshellPage(arch *archetype.Profile, cmd, cmdOut string) string {
	prompt := "$"
	if arch != nil {
		if p := arch.CLIPrompt(); p != "" {
			prompt = strings.TrimSpace(p)
		}
	}
	var sb strings.Builder
	sb.WriteString("<html><head><title>sh</title>" +
		"<style>body{background:#000;color:#0f0;font-family:monospace}" +
		"input{background:#000;color:#0f0;border:1px solid #0f0;width:80%}</style></head><body>")
	sb.WriteString("<pre>uid=33(www-data) gid=33(www-data) groups=33(www-data)\n")
	sb.WriteString(prompt + " " + htmlEscape(cmd) + "\n")
	if cmdOut != "" {
		sb.WriteString(htmlEscape(strings.ReplaceAll(cmdOut, "\r\n", "\n")))
	}
	sb.WriteString("</pre>")
	sb.WriteString("<form method=\"POST\"><input name=\"cmd\" autofocus placeholder=\"command\">" +
		"<input type=\"submit\" value=\"run\"></form></body></html>")
	return sb.String()
}

// handleWebshell processes a detected web-shell request: it always
// captures + flags, and (when active) runs the command through the canned
// shell emulator. Returns the HTML body to serve when active, or "" when
// the caller should fall through to its normal response (detect-only).
func handleWebshell(res *Result, arch *archetype.Profile, cmd string, active bool) string {
	flagAnomaly(res, "webshell-access-attempt")
	if cmd != "" {
		res.Meta["webshell_cmd"] = safe.SanitizeForLog(cmd)
		flagAnomaly(res, "webshell-command")
	}
	if !active {
		return ""
	}
	out := ""
	if cmd != "" {
		o, anoms := shell.OneShot(arch, cmd)
		out = o
		for _, a := range anoms {
			flagAnomaly(res, a)
		}
	}
	return webshellPage(arch, cmd, out)
}
