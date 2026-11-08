package ui

import (
	"html/template"
	"log/slog"
	"net/http"
	"sort"
	"strings"

	tdocs "github.com/rom/tarpit-honeypot/docs"
	"github.com/rom/tarpit-honeypot/internal/cve"
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
	{"database-backend", "Database backend", "The storage architecture: embedded SQLite at the edge, the EventStore seam, and the optional PostgreSQL backend for fleet aggregators."},
	{"archetypes", "OS / device archetypes", "The host personalities the sensor can present."},
	{"attribution", "ATT&CK / D3FEND / CVE", "How interactions map to ATT&CK, D3FEND, and the CVE/CWE/CPE/EPSS catalog."},
	{"CVE", "CVE catalog", "The full CVE reference (auto-generated from internal/cve): top-10s by product, vendor, protocol and year; CVSS severity and CWE weakness-class mappings; and the protocol- and product-focused cross-references."},
	{"ot", "ICS / OT decoys", "The industrial-protocol decoy suite: supported protocols, emulated commands, attacker-intent + ATT&CK-for-ICS mapping, the deception model, and limitations."},
	{"AGENTIC", "Agentic attacks", "Detecting and turning the tables on autonomous LLM agents: the agent handler, protocol/Web-Bot-Auth/crawler recognition, confidence scoring, multi-turn correlation, the extract/provoke/disrupt bait ladder, counter-exfil, the agent provocateur, prompt analysis, decoys/lures/tokens, and the shipped rules."},
	{"attack-tools", "Attack-tool fingerprinting", "The scanners and attack tools the sensor recognizes: how identification works, the categories, and what's covered."},
	{"scripting", "Scripting & dynamics", "How YAML, Lua and YARA shape the sensor: what each format is, where it plugs in, and which to reach for."},
	{"yara", "YARA artifact rules", "The CGO-free YARA engine: the built-in rule pack, the supported subset + modules, per-rule severity, and loading your own rules."},
	{"lua", "Lua service personas", "Writing Lua personas: the persona API, the Lua-language cheat-sheet, the sandbox limits, recipes, and the personas that ship."},
	{"detection-rules", "Detection rules (YAML)", "Detection-as-code: match every event with operator YAML rules — fields, modifiers, recipes, and the shipped rule packs."},
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
	// Generated reference catalogs (from the live handler / CVE / ATT&CK data,
	// so the docs can't drift from what the sensor implements).
	JA         []jaDoc
	Handlers   []handlerDoc
	Techniques []techDoc
	CVEs       []cveDoc
	CWEs       []cve.CWEEntry
}

// docPage carries one rendered Markdown document.
type docPage struct {
	Name string
	Body template.HTML
}

func (s *Server) handleDocs(w http.ResponseWriter, _ *http.Request) {
	p := docsPage{
		UIBind:     s.cfg.Bind,
		Docs:       docLibrary(),
		JA:         jaCatalog(),
		Handlers:   handlerDocs(),
		Techniques: techniqueDocs(),
		CVEs:       cveDocs(),
		CWEs:       cve.CWEs(),
	}
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
	p := docPage{Name: name, Body: renderMarkdown(string(raw), served)}
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
