package cli

import (
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"strings"
)

// cmdGenToken prints (or writes) a random unguessable canary token. The output
// is shaped per the --type flag so the operator can paste it directly into a
// config or a bait artifact. Every type embeds the SAME callback identity (a
// token under the operator's canary domain / canary listener), so a hit on the
// dns / url_canary / ssrf_canary listener attributes straight back to where the
// token was planted. Inspired by the canarytokens.org token zoo.
//
//	dns        - "<hex>-<label>.<base-domain>"            (DNS lookup = tripped)
//	url        - "/__canary__/<hex>-<label>"              (url_canary path)
//	ssrf       - "http://<base>/ssrf/<hex>-<label>"       (SSRF / webhook / XXE)
//	hex        - just the hex string                      (generic secret)
//	doc        - decoy .docx with an external-relationship callback (opens → fetch)
//	log4shell  - "${jndi:ldap://<hex>.<base>:1389/<hex>}" (JNDI lookup = tripped)
//	aws        - a fake AWS access-key/secret pair        (use → CloudTrail alert)
//	css        - a CSS web-bug snippet                    (cloned-page load = fetch)
//	mcp        - an MCP server config JSON                (agent connects → fetch)
//	wireguard  - a wg0.conf with a canary Endpoint host   (connect → DNS lookup)
//	folder     - a desktop.ini with a UNC IconResource    (folder browse → SMB/DNS)
//
// Tokens default to 64 bits of entropy. That's overkill for guess-prevention
// but short enough to fit cleanly in subdomains, paths, and filenames.
func cmdGenToken(args []string) error {
	fs := flag.NewFlagSet("gen-token", flag.ContinueOnError)
	kind := fs.String("type", "dns", "token type: dns | url | ssrf | hex | doc | log4shell | aws | css | mcp | wireguard | folder")
	label := fs.String("label", "", "optional human-readable suffix (e.g. \"prod-cdb\")")
	bits := fs.Int("bits", 64, "bits of entropy (multiple of 8 between 32 and 256)")
	domain := fs.String("domain", "canary.example.com", "base domain / canary host the token calls back to")
	out := fs.String("o", "", "output file for file-producing types (doc | mcp | wireguard | folder)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *bits%8 != 0 || *bits < 32 || *bits > 256 {
		return fmt.Errorf("--bits must be a multiple of 8 between 32 and 256")
	}
	buf := make([]byte, *bits/8)
	if _, err := rand.Read(buf); err != nil {
		return err
	}
	token := hex.EncodeToString(buf)

	suffix := ""
	if l := sanitizeLabel(*label); l != "" {
		suffix = "-" + l
	}
	base := strings.TrimPrefix(*domain, ".")
	tok := token + suffix // the paste-able token id

	switch *kind {
	case "dns":
		fmt.Printf("%s.%s\n", tok, base)
	case "url":
		fmt.Printf("/__canary__/%s\n", tok)
	case "ssrf":
		// A full callback URL to plant in an SSRF-able parameter, webhook
		// field, or XXE entity. Point it at an ssrf_canary listener.
		fmt.Printf("http://%s/ssrf/%s\n", base, tok)
	case "doc":
		// A decoy Word document whose embedded external relationship points at
		// the callback URL: opening it in Word triggers an outbound fetch the
		// ssrf_canary / url-canary listener records. Write the .docx to disk.
		callback := fmt.Sprintf("http://%s/doc/%s", base, tok)
		path := *out
		if path == "" {
			path = "canary-" + tok + ".docx"
		}
		if err := writeDocxCanary(path, callback); err != nil {
			return fmt.Errorf("doc canary: %w", err)
		}
		fmt.Printf("wrote %s (callback: %s)\n", path, callback)
	case "log4shell":
		// A JNDI lookup string to paste into any attacker-loggable field (a
		// User-Agent, a username, a search box). A log4j that expands it resolves
		// the <token>.<base> host first — the DNS canary catches that lookup, and
		// a full LDAP fetch is the high-signal "exploited" case.
		fmt.Printf("${jndi:ldap://%s.%s:1389/%s}\n", tok, base, token)
	case "aws":
		// A canarytokens-style fake AWS credential pair. Drop it in a decoy
		// ~/.aws/credentials or an .env; its USE (an API call) trips your
		// CloudTrail alert — wire the access-key-id into your SIEM watchlist.
		// Expand the entropy so the shape is stable regardless of --bits.
		h := hex.EncodeToString(buf)
		for len(h) < 56 {
			h += hex.EncodeToString(buf)
		}
		ak := "AKIA" + strings.ToUpper(h[:16])
		sk := h[16:56] // 40-char secret-shaped
		fmt.Printf("aws_access_key_id = %s\naws_secret_access_key = %s\n", ak, sk)
		fmt.Printf("# track %s in your CloudTrail / SIEM watchlist\n", ak)
	case "css":
		// A CSS web-bug to embed in a cloned page / email template. Any render
		// fetches the background image from the url_canary listener.
		fmt.Printf("/* canary */ body::before{content:\"\";background:url(\"https://%s/css/%s\")}\n", base, tok)
	case "mcp":
		// An MCP server configuration an agent may load and connect to. The
		// moment an agent opens a session to the canary MCP URL, the url_canary
		// listener records it — a strong "an AI agent read my config" signal.
		callback := fmt.Sprintf("https://%s/mcp/%s", base, tok)
		body := "{\n  \"mcpServers\": {\n    \"internal-ops\": {\n" +
			"      \"url\": \"" + callback + "\",\n" +
			"      \"transport\": \"sse\",\n" +
			"      \"headers\": { \"Authorization\": \"Bearer mcp_" + token + "\" }\n" +
			"    }\n  }\n}\n"
		path := *out
		if path == "" {
			path = "mcp.json"
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			return fmt.Errorf("mcp token: %w", err)
		}
		fmt.Printf("wrote %s (callback: %s)\n", path, callback)
	case "wireguard":
		// A WireGuard client config whose Endpoint resolves the canary host on
		// connect — the DNS canary catches the lookup. Keys are decoy bytes.
		host := fmt.Sprintf("%s.%s", tok, base)
		body := "[Interface]\nPrivateKey = " + b64Decoy(buf, 32) + "\nAddress = 10.13.37.2/32\nDNS = 10.13.37.1\n\n" +
			"[Peer]\nPublicKey = " + b64Decoy(append(buf, 0x01), 32) + "\nAllowedIPs = 0.0.0.0/0\n" +
			"Endpoint = " + host + ":51820\nPersistentKeepalive = 25\n"
		path := *out
		if path == "" {
			path = "wg0.conf"
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			return fmt.Errorf("wireguard token: %w", err)
		}
		fmt.Printf("wrote %s (endpoint: %s:51820)\n", path, host)
	case "folder":
		// A Windows desktop.ini that points an icon at a UNC path on the canary
		// host. Simply BROWSING the folder in Explorer triggers an SMB/DNS lookup
		// of \\<token>.<base> — the DNS canary catches it. Drop it in a juicy dir.
		host := fmt.Sprintf("%s.%s", tok, base)
		body := "[.ShellClassInfo]\r\nIconResource=\\\\" + host + "\\share\\icon.ico,0\r\n" +
			"[ViewState]\r\nMode=\r\nVid=\r\nFolderType=Generic\r\n"
		path := *out
		if path == "" {
			path = "desktop.ini"
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			return fmt.Errorf("folder token: %w", err)
		}
		fmt.Printf("wrote %s (UNC host: \\\\%s\\share)\n", path, host)
	case "hex":
		fmt.Println(tok)
	default:
		return fmt.Errorf("unknown --type %q (want dns|url|ssrf|hex|doc|log4shell|aws|css|mcp|wireguard|folder)", *kind)
	}
	return nil
}

// b64Decoy returns a WireGuard-key-shaped 44-char base64 string derived from
// seed bytes (decoy key material, not a real key).
func b64Decoy(seed []byte, n int) string {
	const a = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	// Expand/trim seed to n bytes deterministically.
	b := make([]byte, n)
	for i := 0; i < n; i++ {
		b[i] = seed[i%len(seed)] ^ byte(i*31)
	}
	out := make([]byte, 0, 44)
	for i := 0; i < 43; i++ {
		out = append(out, a[int(b[i%n])%len(a)])
	}
	out = append(out, '=')
	return string(out)
}

// sanitizeLabel keeps only DNS-safe characters so the output is paste-able
// into either a hostname or a URL path without surprises.
func sanitizeLabel(s string) string {
	if s == "" {
		return ""
	}
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9':
			out = append(out, c)
		case c >= 'A' && c <= 'Z':
			out = append(out, c+32)
		case c == '-' || c == '_':
			out = append(out, c)
		}
	}
	return string(out)
}
