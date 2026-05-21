package cli

import (
	"flag"
	"fmt"
	"strings"

	"github.com/rom/tarpit-honeypot/internal/cve"
	"github.com/rom/tarpit-honeypot/internal/toolfp"
)

// cmdIdentify runs the sensor's offline fingerprint engine over signals
// you supply on the command line — a User-Agent, request path, SSH client
// id, JA3, or a raw request payload — and prints the same verdict the
// live listener would attach to an event. It's a tuning / triage aid:
// paste a string out of a log and see what tool the sensor calls it and
// whether it would fire a CVE rule. No network, no config.
func cmdIdentify(args []string) error {
	fs := flag.NewFlagSet("identify", flag.ContinueOnError)
	ua := fs.String("ua", "", "HTTP User-Agent to classify")
	path := fs.String("path", "", "HTTP request path to classify")
	method := fs.String("method", "GET", "HTTP method (with --path/--ua)")
	headers := fs.String("headers", "", "comma-separated HTTP header names seen")
	sshID := fs.String("ssh", "", "SSH client id, e.g. SSH-2.0-libssh2_1.9.0")
	ja3 := fs.String("ja3", "", "JA3 TLS fingerprint (md5 hex)")
	payload := fs.String("payload", "", "raw request bytes to scan for CVE exploit signatures")
	handler := fs.String("handler", "http", "handler/service context for --payload CVE matching")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *ua == "" && *path == "" && *sshID == "" && *ja3 == "" && *payload == "" {
		return fmt.Errorf("supply at least one of --ua, --path, --ssh, --ja3, --payload")
	}

	if *ua != "" || *path != "" {
		var keys []string
		if *headers != "" {
			for _, h := range strings.Split(*headers, ",") {
				if h = strings.ToLower(strings.TrimSpace(h)); h != "" {
					keys = append(keys, h)
				}
			}
		}
		v := toolfp.IdentifyHTTP(toolfp.HTTPSignals{
			Method: *method, Path: *path, UserAgent: *ua, HeaderKeys: keys,
		})
		fmt.Println("http:")
		fmt.Printf("  tools:      %s\n", joinOrDash(v.Tools))
		fmt.Printf("  automation: %t\n", v.Automation)
		fmt.Printf("  reason:     %s\n", dash(v.Reason))
	}

	if *sshID != "" {
		fmt.Println("ssh:")
		fmt.Printf("  tools:      %s\n", joinOrDash(toolfp.IdentifySSH(*sshID)))
	}

	if *ja3 != "" {
		fmt.Println("tls:")
		fmt.Printf("  tool:       %s\n", dash(toolfp.IdentifyTLS(*ja3)))
	}

	if *payload != "" {
		hits := cve.MatchPayload(*handler, *payload)
		fmt.Printf("cve (handler %q):\n", *handler)
		if len(hits) == 0 {
			fmt.Println("  (no exploit signatures matched)")
		}
		for _, r := range hits {
			fmt.Printf("  %-18s %5.1f  %s\n", r.ID, r.CVSS, r.Name)
		}
	}
	return nil
}

func joinOrDash(xs []string) string {
	if len(xs) == 0 {
		return "-"
	}
	return strings.Join(xs, ", ")
}
