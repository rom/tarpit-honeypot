package cli

import (
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"strings"
)

// cmdGenToken prints a random unguessable canary token. The output is
// shaped per the --type flag so the operator can paste it directly into
// a config or a bait artifact.
//
//	dns  - "<hex>-<label>.<base-domain>"
//	url  - "/__canary__/<hex>-<label>"
//	hex  - just the hex string
//
// Tokens default to 64 bits of entropy. That's overkill for guess-prevention
// but short enough to fit cleanly in subdomains, paths, and filenames.
func cmdGenToken(args []string) error {
	fs := flag.NewFlagSet("gen-token", flag.ContinueOnError)
	kind := fs.String("type", "dns", "token type: dns | url | hex | ssrf")
	label := fs.String("label", "", "optional human-readable suffix (e.g. \"prod-cdb\")")
	bits := fs.Int("bits", 64, "bits of entropy (multiple of 8 between 32 and 256)")
	domain := fs.String("domain", "canary.example.com", "for --type=dns/ssrf, the base domain")
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

	switch *kind {
	case "dns":
		base := strings.TrimPrefix(*domain, ".")
		fmt.Printf("%s%s.%s\n", token, suffix, base)
	case "url":
		fmt.Printf("/__canary__/%s%s\n", token, suffix)
	case "ssrf":
		// A full callback URL to plant in an SSRF-able parameter, webhook
		// field, or XXE entity. Point it at an ssrf_canary listener.
		base := strings.TrimPrefix(*domain, ".")
		fmt.Printf("http://%s/ssrf/%s%s\n", base, token, suffix)
	case "hex":
		fmt.Println(token + suffix)
	default:
		return fmt.Errorf("unknown --type %q (want dns|url|hex|ssrf)", *kind)
	}
	return nil
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
