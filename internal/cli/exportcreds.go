package cli

import (
	"context"
	"encoding/csv"
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
	dedup := fs.Bool("dedup", true, "collapse identical kind/user/secret/service rows")
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
	sort.SliceStable(creds, func(i, j int) bool { return creds[i].Time > creds[j].Time })

	return writeCreds(*format, creds)
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
