package cli

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"encoding/xml"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/store"
	"github.com/rom/tarpit-honeypot/internal/ui"
)

// cmdExportCreds exports the credentials captured in the event store. Credentials
// are reconstructed with the same logic the web UI uses (login pairs, SSH
// auth_attempts, tokens, API keys, SNMP communities, Kerberos tickets, …), then
// filtered by --kind and emitted in the requested format.
func cmdExportCreds(args []string) error {
	fs := flag.NewFlagSet("export-creds", flag.ContinueOnError)
	cfgPath := fs.String("c", "/etc/tarpit-honeypot/config.yaml", "path to config file")
	dataDir := fs.String("data-dir", "", "data directory (overrides config; skips config loading)")
	since := fs.Duration("since", 30*24*time.Hour, "export credentials from events newer than this")
	format := fs.String("format", "json", "output format: json | xml | yaml | csv | txt")
	kind := fs.String("kind", "", "comma-separated credential kinds to include (e.g. password,token,ssh-pubkey); empty = all")
	dedup := fs.Bool("dedup", true, "remove duplicates: collapse identical kind/user/secret/service rows")
	sortBy := fs.String("sort", "time", "sort by: time | source | user | secret | service | kind")
	reverse := fs.Bool("reverse", false, "reverse the sort order")
	exclude := fs.String("exclude", "", "comma-separated columns to omit from the output: timestamp, type, ip, service")
	if err := parseOrUsage(fs, args); err != nil {
		if err == errHelp {
			return nil
		}
		return err
	}
	switch *format {
	case "json", "xml", "yaml", "csv", "txt":
	default:
		return fmt.Errorf("--format must be json, xml, yaml, csv, or txt (got %q)", *format)
	}
	excluded, err := parseExclude(*exclude)
	if err != nil {
		return err
	}
	switch *sortBy {
	case "time", "source", "user", "secret", "service", "kind":
	default:
		return fmt.Errorf("--sort must be time, source, user, secret, service, or kind (got %q)", *sortBy)
	}
	// Optional kind filter.
	var want map[string]bool
	if *kind != "" {
		want = map[string]bool{}
		for _, k := range strings.Split(*kind, ",") {
			if k = strings.TrimSpace(strings.ToLower(k)); k != "" {
				want[k] = true
			}
		}
	}

	dir := *dataDir
	if dir == "" {
		cfg, err := config.Load(*cfgPath)
		if err != nil {
			return fmt.Errorf("export-creds: %w (or pass --data-dir)", err)
		}
		dir = cfg.Sensor.DataDir
	}
	if _, err := os.Stat(filepath.Join(dir, "events.db")); err != nil {
		return fmt.Errorf("export-creds needs the sqlite event store (%s): %w", filepath.Join(dir, "events.db"), err)
	}
	st, err := store.Open(dir, 0)
	if err != nil {
		return err
	}
	defer st.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	evs, err := st.Query(ctx, store.Filter{Since: time.Now().Add(-*since), Limit: 200000})
	if err != nil {
		return err
	}

	var creds []ui.Cred
	seen := map[string]bool{}
	for _, ev := range evs {
		for _, c := range ui.ExtractCreds(ev) {
			if want != nil && !want[strings.ToLower(c.Kind)] {
				continue
			}
			if *dedup {
				key := c.Kind + "\x00" + c.User + "\x00" + c.Secret + "\x00" + c.Service
				if seen[key] {
					continue
				}
				seen[key] = true
			}
			creds = append(creds, c)
		}
	}
	sortCreds(creds, *sortBy, *reverse)

	if len(excluded) == 0 {
		return writeCreds(*format, creds) // default: unchanged behavior
	}
	return writeCredsCols(*format, creds, includedCols(excluded))
}

// credColumns is the canonical ordered output column set. user + secret are the
// credential itself and are never excludable; the rest can be omitted.
var credColumns = []string{"time", "source", "kind", "user", "secret", "service"}

// excludeAliases maps the operator-facing --exclude names to canonical columns.
var excludeAliases = map[string]string{
	"timestamp": "time", "time": "time", "date": "time",
	"type": "kind", "kind": "kind",
	"ip": "source", "ips": "source", "ip-address": "source", "ipaddress": "source", "source": "source",
	"service": "service", "svc": "service",
}

// parseExclude turns the --exclude list into the set of canonical columns to
// omit. user / secret cannot be excluded (they are the captured credential).
func parseExclude(s string) (map[string]bool, error) {
	out := map[string]bool{}
	for _, e := range strings.Split(s, ",") {
		e = strings.TrimSpace(strings.ToLower(e))
		if e == "" {
			continue
		}
		col, ok := excludeAliases[e]
		if !ok {
			return nil, fmt.Errorf("--exclude: unknown field %q (allowed: timestamp, type, ip, service)", e)
		}
		out[col] = true
	}
	return out, nil
}

// includedCols returns credColumns minus the excluded set, preserving order.
func includedCols(excluded map[string]bool) []string {
	cols := make([]string, 0, len(credColumns))
	for _, c := range credColumns {
		if !excluded[c] {
			cols = append(cols, c)
		}
	}
	return cols
}

// credValue returns the string value of a credential column.
func credValue(c ui.Cred, col string) string {
	switch col {
	case "time":
		return c.Time
	case "source":
		return c.Source
	case "kind":
		return c.Kind
	case "user":
		return c.User
	case "secret":
		return c.Secret
	case "service":
		return c.Service
	}
	return ""
}

// writeCredsCols emits the credentials projected onto cols (the column subset
// left after --exclude), honoring the requested format.
func writeCredsCols(format string, creds []ui.Cred, cols []string) error {
	switch format {
	case "csv":
		w := csv.NewWriter(os.Stdout)
		_ = w.Write(cols)
		for _, c := range creds {
			row := make([]string, len(cols))
			for i, col := range cols {
				row[i] = credValue(c, col)
			}
			_ = w.Write(row)
		}
		w.Flush()
		return w.Error()
	case "txt":
		for _, c := range creds {
			parts := make([]string, len(cols))
			for i, col := range cols {
				if v := credValue(c, col); v != "" {
					parts[i] = v
				} else {
					parts[i] = "-"
				}
			}
			fmt.Println(strings.Join(parts, "\t"))
		}
		return nil
	case "json":
		var b bytes.Buffer
		b.WriteByte('[')
		for i, c := range creds {
			if i > 0 {
				b.WriteByte(',')
			}
			b.WriteString("\n  {")
			for j, col := range cols {
				if j > 0 {
					b.WriteString(", ")
				}
				kb, _ := json.Marshal(col)
				vb, _ := json.Marshal(credValue(c, col))
				b.Write(kb)
				b.WriteString(": ")
				b.Write(vb)
			}
			b.WriteByte('}')
		}
		if len(creds) > 0 {
			b.WriteByte('\n')
		}
		b.WriteString("]\n")
		_, err := os.Stdout.Write(b.Bytes())
		return err
	case "yaml":
		rows := make([]map[string]string, 0, len(creds))
		for _, c := range creds {
			m := make(map[string]string, len(cols))
			for _, col := range cols {
				m[col] = credValue(c, col)
			}
			rows = append(rows, m)
		}
		b, err := yaml.Marshal(rows)
		if err != nil {
			return err
		}
		_, err = os.Stdout.Write(b)
		return err
	case "xml":
		var b bytes.Buffer
		b.WriteString(xml.Header[:len(xml.Header)-1] + "\n<credentials>\n")
		for _, c := range creds {
			b.WriteString("  <credential>\n")
			for _, col := range cols {
				var esc bytes.Buffer
				_ = xml.EscapeText(&esc, []byte(credValue(c, col)))
				b.WriteString("    <" + col + ">" + esc.String() + "</" + col + ">\n")
			}
			b.WriteString("  </credential>\n")
		}
		b.WriteString("</credentials>\n")
		_, err := os.Stdout.Write(b.Bytes())
		return err
	}
	return fmt.Errorf("unknown format %q", format)
}

// sortCreds orders the credential rows by the chosen field. "time" is newest-
// first (the default that operators expect); the text fields sort
// ascending/case-insensitively. --reverse flips whichever order was chosen.
func sortCreds(creds []ui.Cred, by string, reverse bool) {
	key := func(c ui.Cred) string {
		switch by {
		case "source":
			return c.Source
		case "user":
			return strings.ToLower(c.User)
		case "secret":
			return strings.ToLower(c.Secret)
		case "service":
			return c.Service
		case "kind":
			return c.Kind
		default:
			return ""
		}
	}
	sort.SliceStable(creds, func(i, j int) bool {
		less := false
		if by == "time" {
			less = creds[i].Time > creds[j].Time // newest first
		} else if ki, kj := key(creds[i]), key(creds[j]); ki != kj {
			less = ki < kj
		} else {
			less = creds[i].Time > creds[j].Time // stable tiebreak: newest first
		}
		if reverse {
			return !less
		}
		return less
	})
}

func writeCreds(format string, creds []ui.Cred) error {
	switch format {
	case "json":
		return writeJSON(creds)
	case "yaml":
		b, err := yaml.Marshal(creds)
		if err != nil {
			return err
		}
		_, err = os.Stdout.Write(b)
		return err
	case "xml":
		type credsDoc struct {
			XMLName xml.Name  `xml:"credentials"`
			Creds   []ui.Cred `xml:"credential"`
		}
		enc := xml.NewEncoder(os.Stdout)
		enc.Indent("", "  ")
		fmt.Println(xml.Header[:len(xml.Header)-1])
		if err := enc.Encode(credsDoc{Creds: creds}); err != nil {
			return err
		}
		fmt.Println()
		return nil
	case "csv":
		w := csv.NewWriter(os.Stdout)
		_ = w.Write([]string{"time", "source", "kind", "user", "secret", "service"})
		for _, c := range creds {
			_ = w.Write([]string{c.Time, c.Source, c.Kind, c.User, c.Secret, c.Service})
		}
		w.Flush()
		return w.Error()
	case "txt":
		for _, c := range creds {
			user := c.User
			if user == "" {
				user = "-"
			}
			fmt.Printf("%s\t%s\t%s\t%s:%s\t%s\n", c.Time, c.Source, c.Kind, user, c.Secret, c.Service)
		}
		return nil
	}
	return fmt.Errorf("unknown format %q", format)
}
