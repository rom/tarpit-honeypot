package ui

import (
	"context"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/rom/tarpit-honeypot/internal/event"
	"github.com/rom/tarpit-honeypot/internal/mitre"
)

const handlerViewWindow = 24 * time.Hour
const handlerViewScanMax = 20000

// handlerView is the per-handler focused dossier: how much that decoy was
// probed vs. attacked vs. successfully engaged, when, by whom, and the full set
// of intents / tools / ATT&CK / D3FEND / interpretations observed on it.
type handlerView struct {
	Handler    string
	RangeKey   string
	RangeLabel string
	RangeLinks []rangeLink

	Attempts   int // total events on this handler
	Attacks    int // events classified as attacks/misuse (not benign recon)
	Successful int // events where the decoy let the attacker in / the exploit landed
	Sources    int // distinct source IPs

	FirstAttempt time.Time
	LastAttempt  time.Time
	HasAttack    bool
	FirstAttack  time.Time
	LastAttack   time.Time

	Intents         []barRow // meta.intent, counted, linking to the filtered events
	Interpretations []barRow // the application-level interaction phase
	Severities      []barRow
	Tactics         []string
	Techniques      []barRow // ATT&CK techniques → drill-down
	Defenses        []string // D3FEND countermeasure ids
	Tools           []string
	Anomalies       []string // distinct protocol-misuse markers seen

	IPv4 []handlerIP
	IPv6 []handlerIP
}

// handlerIP is one attacker address seen on the handler, with reverse DNS.
type handlerIP struct {
	IP    string
	RDNS  string
	Count int
	Sev   string
}

// eventIsAttack reports whether an event is an actual attack/misuse on the
// decoy rather than a benign banner-grab / recon touch.
func eventIsAttack(ev *event.Event) bool {
	return isAttackEvent(ev) || sevRank(ev.Severity.String()) >= 3 || len(ev.Anomalies) > 0 || len(eventCVEs(ev)) > 0
}

// eventSucceeded reports whether the decoy let the attacker progress — accepted
// a login, dropped to a shell, recorded a session, or the exploit/drop chain
// landed. This is the "successful attack" the operator cares about.
func eventSucceeded(ev *event.Event) bool {
	m := ev.Meta
	if m == nil {
		return false
	}
	if _, ok := m["accepted_user"]; ok {
		return true
	}
	if v, ok := m["auth_accepted"].(bool); ok && v {
		return true
	}
	if _, ok := m["session_cast"]; ok {
		return true
	}
	if len(metaStrings(m, "shell_commands")) > 0 {
		return true
	}
	if c, _ := m["exec_command"].(string); c != "" {
		return true
	}
	for _, a := range ev.Anomalies {
		if strings.Contains(a, "drop-chain-complete") || strings.Contains(a, "webshell") || strings.HasPrefix(a, "shell-") {
			return true
		}
	}
	return false
}

func buildHandlerView(name string, evs []*event.Event) handlerView {
	v := handlerView{Handler: name}
	intent := map[string]int{}
	phase := map[string]int{}
	sev := map[string]int{}
	tech := map[string]int{}
	tacSet := map[string]bool{}
	defSet := map[string]bool{}
	toolSet := map[string]bool{}
	anomSet := map[string]bool{}
	type ipAgg struct {
		count int
		rdns  string
		sev   string
	}
	ips := map[string]*ipAgg{}

	for _, ev := range evs {
		if ev.Handler != name {
			continue
		}
		v.Attempts++
		if v.FirstAttempt.IsZero() || ev.Time.Before(v.FirstAttempt) {
			v.FirstAttempt = ev.Time
		}
		if ev.Time.After(v.LastAttempt) {
			v.LastAttempt = ev.Time
		}
		if eventIsAttack(ev) {
			v.Attacks++
			if !v.HasAttack || ev.Time.Before(v.FirstAttack) {
				v.FirstAttack = ev.Time
			}
			if ev.Time.After(v.LastAttack) {
				v.LastAttack = ev.Time
			}
			v.HasAttack = true
		}
		if eventSucceeded(ev) {
			v.Successful++
		}
		if it, _ := ev.Meta["intent"].(string); it != "" {
			intent[it]++
		}
		if p := classifyInteraction(ev); p != "" {
			phase[p]++
		}
		if s := ev.Severity.String(); s != "" {
			sev[s]++
		}
		tag := eventTag(ev)
		for _, t := range tag.Tactics {
			tacSet[t] = true
		}
		for _, t := range tag.Techniques {
			tech[t]++
		}
		for _, d := range mitre.DefensesFor(tag.Techniques) {
			defSet[d] = true
		}
		for _, d := range ev.MitreDefenses {
			defSet[d] = true
		}
		for _, tl := range metaStrings(ev.Meta, "tools") {
			toolSet[tl] = true
		}
		for _, a := range ev.Anomalies {
			anomSet[a] = true
		}
		if ip := ev.Source.IP; ip != "" {
			a := ips[ip]
			if a == nil {
				a = &ipAgg{}
				ips[ip] = a
			}
			a.count++
			if r, _ := ev.Meta["rdns"].(string); r != "" {
				a.rdns = r
			}
			if sevRank(ev.Severity.String()) > sevRank(a.sev) {
				a.sev = ev.Severity.String()
			}
		}
	}

	v.Sources = len(ips)
	v.Intents = topBars(intent, 20, "/events?intent=")
	v.Interpretations = topBars(phase, 20, "")
	v.Severities = sevBars(sev)
	v.Techniques = topBars(tech, 20, "/attack/technique?id=")
	for i := range v.Techniques {
		if nm := techShortName(v.Techniques[i].Label); nm != "" {
			v.Techniques[i].Label = v.Techniques[i].Label + " · " + nm
		}
	}
	v.Tactics = sortedSetKeys(tacSet, 64)
	v.Defenses = sortedSetKeys(defSet, 64)
	v.Tools = sortedSetKeys(toolSet, 64)
	v.Anomalies = sortedSetKeys(anomSet, 128)

	for ip, a := range ips {
		row := handlerIP{IP: ip, RDNS: a.rdns, Count: a.count, Sev: a.sev}
		if strings.Contains(ip, ":") {
			v.IPv6 = append(v.IPv6, row)
		} else {
			v.IPv4 = append(v.IPv4, row)
		}
	}
	sortHandlerIPs(v.IPv4)
	sortHandlerIPs(v.IPv6)
	return v
}

// sevBars renders a severity count map as bars ordered critical→low with the
// severity tint class + a pivot to the filtered events.
func sevBars(m map[string]int) []barRow {
	order := []string{"critical", "high", "medium", "low"}
	max := 0
	for _, n := range m {
		if n > max {
			max = n
		}
	}
	var out []barRow
	for _, s := range order {
		if n := m[s]; n > 0 {
			out = append(out, barRow{Label: s, Count: n, Pct: pct(n, max), Class: "sev-" + s, Href: "/events?severity=" + s})
		}
	}
	return out
}

func sortHandlerIPs(rows []handlerIP) {
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Count != rows[j].Count {
			return rows[i].Count > rows[j].Count
		}
		return rows[i].IP < rows[j].IP
	})
}

func (s *Server) handleHandlerView(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSpace(r.URL.Query().Get("name"))
	if name == "" {
		http.Redirect(w, r, "/events", http.StatusSeeOther)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	dur, rkey, rlabel, rlinks := pageRange(r, "/handler")
	evs, err := s.windowEvents(ctx, dur, handlerViewScanMax)
	if err != nil {
		serverError(w, r.URL.Path, err)
		return
	}
	view := buildHandlerView(name, evs)
	view.RangeKey, view.RangeLabel, view.RangeLinks = rkey, rlabel, rlinks
	view.Techniques = s.linkTechBars(view.Techniques) // out-link techniques to attack.mitre.org if enabled
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tmpl.ExecuteTemplate(w, "handlerview", view); err != nil {
		slog.Warn("ui: render handlerview", "err", err)
	}
}
