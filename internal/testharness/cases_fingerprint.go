package testharness

import (
	"context"
	"fmt"
	"os/exec"
	"time"
)

func init() {
	// fingerprint: emit traffic that mimics a known scanner/attack tool and
	// confirm the honeypot's client-classification layer detects it. Verified
	// via the API; skips cleanly without one (or without a matching endpoint).
	RegisterGen(CatFingerprint, func(cfg *Config) []Case {
		if cfg.Mode != "network" {
			return nil
		}
		var out []Case

		var httpEP *Endpoint
		var sshEP *Endpoint
		for i := range cfg.Endpoints {
			switch cfg.Endpoints[i].Handler {
			case "http", "https":
				if httpEP == nil {
					httpEP = &cfg.Endpoints[i]
				}
			case "ssh", "ssh_interactive":
				if sshEP == nil {
					sshEP = &cfg.Endpoints[i]
				}
			}
		}

		// HTTP User-Agent / probe fingerprints for the common scanners.
		tools := []struct{ id, ua, tool string }{
			{"nmap", "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)", "nmap"},
			{"nessus", "Nessus SOAP v0.0.1 (Nessus.org)", "nessus"},
			{"openvas", "Mozilla/5.0 [en] (X11, U; OpenVAS-VT 22.4)", "openvas"},
			{"nikto", "Mozilla/5.00 (Nikto/2.5.0) (Evasions:None) (Test:Port Check)", "nikto"},
			{"nuclei", "Nuclei - Open-source project (github.com/projectdiscovery/nuclei)", "nuclei"},
			{"sqlmap", "sqlmap/1.7.11#stable (https://sqlmap.org)", "sqlmap"},
			{"masscan", "masscan/1.3 (https://github.com/robertdavidgraham/masscan)", "masscan"},
			{"metasploit", "Mozilla/5.0 (compatible; Metasploit RSPEC)", "metasploit"},
			{"zgrab", "Mozilla/5.0 zgrab/0.x", "zgrab"},
			{"wpscan", "WPScan v3.8.25 (https://wpscan.com/wordpress-security-scanner)", "wpscan"},
		}
		if httpEP != nil {
			for _, tdef := range tools {
				tdef, ep := tdef, *httpEP
				out = append(out, Case{
					ID: "fingerprint/http-" + tdef.id, Category: CatFingerprint, Endpoint: ep.Label,
					Title: "detect " + tdef.id + " (HTTP UA)",
					Fn: func(ctx context.Context, r *Run) (Status, string, error) {
						req := "GET /?id=1 HTTP/1.1\r\nHost: target\r\nUser-Agent: " + tdef.ua + "\r\nAccept: */*\r\nConnection: close\r\n\r\n"
						_, _ = probe(ctx, r.Target, ep, []byte(req))
						return verifyTool(ctx, r, tdef.tool)
					},
				})
			}
		}
		if sshEP != nil {
			ep := *sshEP
			out = append(out, Case{
				ID: "fingerprint/ssh-scanner", Category: CatFingerprint, Endpoint: ep.Label,
				Title: "detect scanner SSH client id",
				Fn: func(ctx context.Context, r *Run) (Status, string, error) {
					_, _ = probe(ctx, r.Target, ep, []byte("SSH-2.0-Nmap-SSH2-Hostkey\r\n"))
					st, d := verifyScan(ctx, r, MatchAnomaly("ssh-id-not-ssh"), MatchTool("nmap"), MatchRulePrefix("listener:"))
					return st, d, nil
				},
			})
		}

		// Optional: drive the REAL nmap if it's installed (service/version scan).
		if _, err := exec.LookPath("nmap"); err == nil && len(cfg.Endpoints) > 0 {
			out = append(out, Case{
				ID: "fingerprint/nmap-sV", Category: CatFingerprint,
				Title: "real nmap -sV service scan",
				Fn: func(ctx context.Context, r *Run) (Status, string, error) {
					ports := scanPorts(r.Cfg)
					portList := ""
					for i, p := range ports {
						if i > 0 {
							portList += ","
						}
						portList += itoa(p)
					}
					cctx, cancel := context.WithTimeout(ctx, 90*time.Second)
					defer cancel()
					err := exec.CommandContext(cctx, "nmap", "-sV", "-T4", "-Pn", "-p", portList, r.Cfg.Host).Run()
					if err != nil {
						return StatusError, "nmap run failed: " + err.Error(), nil
					}
					st, d := verifyScan(ctx, r, MatchRulePrefix("scananalysis:"), MatchTool("nmap"), MatchRulePrefix("sniffer:tcp_"), MatchRulePrefix("correlate:port_scan"))
					return st, "ran nmap -sV; " + d, nil
				},
			})
		}
		return out
	})
}

func verifyTool(ctx context.Context, r *Run, tool string) (Status, string, error) {
	if r.API == nil {
		return StatusSkip, "sent " + tool + " signature; set verify.url to confirm detection", nil
	}
	time.Sleep(400 * time.Millisecond)
	detected, checked := r.API.Detected(ctx, MatchTool(tool))
	if !checked {
		return StatusSkip, "verify API unreachable", nil
	}
	if detected {
		return StatusPass, "honeypot identified " + tool, nil
	}
	return StatusFail, fmt.Sprintf("honeypot did NOT identify %s", tool), nil
}
