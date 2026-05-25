package ui

import (
	"html/template"
	"log/slog"
	"net/http"
	"sort"
	"strings"

	tdocs "github.com/rom/tarpit-honeypot/docs"
)

// ---- docs tab ----

// docLink is one entry in the in-product documentation library.
type docLink struct {
	Name  string // base name without .md (the /docs/<name> slug)
	Title string
	Desc  string
}

// docCatalog is the curated, ordered library shown on the docs index. Only
// entries whose Markdown file is actually embedded are listed (availableDocs);
// any embedded doc missing here is appended alphabetically so nothing is hidden.
var docCatalog = []docLink{
	{"webui", "Web UI walkthrough", "Every tab plus the cross-cutting concepts: the event model, ATT&CK/D3FEND attribution, the fleet view, and the IOC view."},
	{"usage", "Usage / operating guide", "Day-to-day operation: running a sensor, reading the console, tuning detection, and the fleet roles."},
	{"config", "Configuration reference", "Every setting, grouped by subsystem, with examples."},
	{"cli", "CLI reference", "Every subcommand and flag (run, validate, the catalog and export commands)."},
	{"fleet", "Fleet & aggregation", "Build a sensor fleet: roles, topologies, the fleet:* detectors, tuning, and troubleshooting."},
	{"ioc", "Indicators of compromise", "What becomes an IOC, the de-duplicated store, ioc:* events, and every export path."},
	{"threat-intel-exports", "Threat-intel exports", "STIX 2.1 / TAXII 2.1 / MISP, the downward intel feed, and the CEF/LEEF/OCSF SIEM sinks."},
	{"hardening", "Hardening", "Running the sensor safely: sandbox, egress allowlist, drop-privileges, and safe exposure."},
	{"internals", "Internals", "The architecture and how the subsystems fit together."},
	{"archetypes", "OS / device archetypes", "The host personalities the sensor can present."},
	{"attribution", "ATT&CK / D3FEND / CVE", "How interactions map to ATT&CK, D3FEND, and the CVE/CWE/CPE/EPSS catalog."},
	{"tcp-stack", "TCP stack", "The userspace TCP/IP stack behind the honeynet responders."},
	{"design", "Design", "Design goals and the rationale behind the sensor."},
	{"testharness", "Test harness", "The QA harness for exercising the sensor."},
	{"INTEGRATIONS", "Integrations", "Wiring the sensor into SIEMs and downstream tooling."},
	{"README", "Documentation index", "The top-level documentation map."},
	{"FAQ", "FAQ", "Common questions, grouped by topic."},
}

// docsPage carries the documentation library plus a small "this deployment"
// section so the docs reflect the running sensor.
type docsPage struct {
	Listeners int
	Networks  int
	Hosts     int
	DevicesOn bool
	UIBind    string
	Docs      []docLink
}

// docPage carries one rendered Markdown document.
type docPage struct {
	Title string
	Name  string
	Body  template.HTML
}

func (s *Server) handleDocs(w http.ResponseWriter, _ *http.Request) {
	p := docsPage{UIBind: s.cfg.Bind, Docs: docLibrary()}
	if s.fullConfig != nil {
		p.Listeners = len(s.fullConfig.Listeners)
		p.Networks = len(s.fullConfig.Honeynets)
		p.DevicesOn = s.fullConfig.Devices.Enabled
	}
	if s.topo != nil {
		p.Hosts = len(s.topo.HostsInNetwork(""))
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tmpl.ExecuteTemplate(w, "docs", p); err != nil {
		slog.Warn("ui: render docs", "err", err)
	}
}

// handleDoc renders a single embedded Markdown document at /docs/<name>.
func (s *Server) handleDoc(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/docs/")
	name = strings.TrimSuffix(name, "/")
	if name == "" {
		http.Redirect(w, r, "/docs", http.StatusFound)
		return
	}
	served := availableDocs()
	if !served[name] {
		http.NotFound(w, r)
		return
	}
	raw, err := tdocs.FS.ReadFile(name + ".md")
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	p := docPage{Title: docTitle(name), Name: name, Body: renderMarkdown(string(raw), served)}
	if err := s.tmpl.ExecuteTemplate(w, "doc", p); err != nil {
		slog.Warn("ui: render doc", "err", err, "name", name)
	}
}

// availableDocs returns the set of doc base names embedded in the binary.
func availableDocs() map[string]bool {
	m := map[string]bool{}
	ents, err := tdocs.FS.ReadDir(".")
	if err != nil {
		return m
	}
	for _, e := range ents {
		if n := e.Name(); strings.HasSuffix(n, ".md") {
			m[strings.TrimSuffix(n, ".md")] = true
		}
	}
	return m
}

// docLibrary returns the catalog filtered to embedded docs, with any embedded
// doc not in the curated list appended alphabetically.
func docLibrary() []docLink {
	served := availableDocs()
	var out []docLink
	seen := map[string]bool{}
	for _, d := range docCatalog {
		if served[d.Name] {
			out = append(out, d)
			seen[d.Name] = true
		}
	}
	var extra []string
	for name := range served {
		if !seen[name] {
			extra = append(extra, name)
		}
	}
	sort.Strings(extra)
	for _, name := range extra {
		out = append(out, docLink{Name: name, Title: name})
	}
	return out
}

func docTitle(name string) string {
	for _, d := range docCatalog {
		if d.Name == name {
			return d.Title
		}
	}
	return name
}
