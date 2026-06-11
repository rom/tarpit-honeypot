package ui

import (
	"context"
	"log/slog"
	"net/http"
	"sort"
	"strconv"
	"time"

	"github.com/rom/tarpit-honeypot/internal/event"
	"github.com/rom/tarpit-honeypot/internal/store"
)

// Credential analytics: aggregates every captured login attempt (the same
// credentials the captures page / export-creds surface) into top users /
// passwords, length + composition distributions, a per-source spray-vs-brute
// classification, and a reuse table (the same secret from many sources /
// services — shared wordlists or one actor rotating IPs). The honeypot's
// near-zero false-positive rate makes these unusually clean.

type credView struct {
	RangeLabel string
	RangeLinks []rangeLink
	Total      int
	Users      int
	Passwords  int
	Sources    int
	Figs       []chartFig
	Spray      []sprayRow
	Reuse      []reuseRow
	Scanned    int
	Empty      bool
}

type sprayRow struct {
	Source    string
	Users     int
	Passwords int
	Attempts  int
	Verdict   string
}

type reuseRow struct {
	Secret   string
	Sources  int
	Services int
	Count    int
}

func (s *Server) handleCredentials(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 6*time.Second)
	defer cancel()
	win := summaryRange(r.URL.Query().Get("range"))
	since := time.Now().Add(-win.dur)
	// NoPayload: credentials are read from event meta (extractCreds), never the
	// raw payload blob, so skip the payload column + per-row banner subquery —
	// the heavy part of the scan that pushed this page over its deadline at
	// 100k+ events.
	evs, err := s.query(ctx, store.Filter{Since: since, Limit: 20000, NoPayload: true})
	if err != nil {
		serverError(w, r.URL.Path, err)
		return
	}
	v := buildCredentials(evs)
	v.RangeLabel = win.label
	v.RangeLinks = rangeLinksFor("/credentials", win.key)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tmpl.ExecuteTemplate(w, "credentials", v); err != nil {
		slog.Warn("ui: render credentials", "err", err)
	}
}

func buildCredentials(evs []*event.Event) credView {
	v := credView{Scanned: len(evs)}
	userCount := map[string]int{}
	passCount := map[string]int{}
	lenCount := map[int]int{}
	complexity := map[string]int{}
	srcUsers := map[string]map[string]bool{}
	srcPass := map[string]map[string]bool{}
	srcAttempts := map[string]int{}
	secretSrc := map[string]map[string]bool{}
	secretSvc := map[string]map[string]bool{}
	secretCount := map[string]int{}
	bySvc := map[string]int{} // credential captures grouped by service (ssh/ftp/telnet/…)
	userSet, passSet, srcSet := map[string]bool{}, map[string]bool{}, map[string]bool{}
	total := 0

	for _, ev := range evs {
		ip := ev.Source.IP
		for _, c := range extractCreds(ev) {
			if c.Kind != "" && c.Kind != "password" { // tokens/tickets/communities live on /captures
				continue
			}
			if c.User == "" && c.Pass == "" {
				continue
			}
			total++
			if c.Service != "" {
				bySvc[c.Service]++
			}
			if c.User != "" {
				userCount[c.User]++
				userSet[c.User] = true
			}
			if c.Pass != "" {
				passCount[c.Pass]++
				passSet[c.Pass] = true
				lenCount[len(c.Pass)]++
				complexity[passClass(c.Pass)]++
				secretCount[c.Pass]++
				if secretSrc[c.Pass] == nil {
					secretSrc[c.Pass] = map[string]bool{}
				}
				if ip != "" {
					secretSrc[c.Pass][ip] = true
				}
				if secretSvc[c.Pass] == nil {
					secretSvc[c.Pass] = map[string]bool{}
				}
				if c.Service != "" {
					secretSvc[c.Pass][c.Service] = true
				}
			}
			if ip != "" {
				srcSet[ip] = true
				srcAttempts[ip]++
				if srcUsers[ip] == nil {
					srcUsers[ip] = map[string]bool{}
				}
				if c.User != "" {
					srcUsers[ip][c.User] = true
				}
				if srcPass[ip] == nil {
					srcPass[ip] = map[string]bool{}
				}
				if c.Pass != "" {
					srcPass[ip][c.Pass] = true
				}
			}
		}
	}
	if total == 0 {
		v.Empty = true
		return v
	}
	v.Total, v.Users, v.Passwords, v.Sources = total, len(userSet), len(passSet), len(srcSet)

	// Where the captured logins came from — compare ssh / ftp / telnet / … so an
	// operator can see which service is bearing the credential-attack load.
	if len(bySvc) > 0 {
		v.Figs = append(v.Figs,
			chartFigure("pie", "Credential captures by service", map[string]any{"slices": slicesFromMap(bySvc), "donut": true}),
			chartFigure("hbar", "Credential captures by service", map[string]any{"series": topBarsFromMap(bySvc, 20)}),
		)
	}
	v.Figs = append(v.Figs,
		chartFigure("hbar", "Top usernames tried", map[string]any{"series": topBarsFromMap(userCount, 20)}),
		chartFigure("hbar", "Top passwords tried", map[string]any{"series": topBarsFromMap(passCount, 20)}),
	)
	lens := sortedIntKeys(lenCount)
	lbars := make([]chBar, 0, len(lens))
	for _, l := range lens {
		lbars = append(lbars, chBar{Label: strconv.Itoa(l), Value: lenCount[l]})
	}
	v.Figs = append(v.Figs,
		chartFigure("bar", "Password length distribution", map[string]any{"series": lbars}),
		chartFigure("pie", "Password composition", map[string]any{"slices": slicesFromMap(complexity), "donut": true}),
	)
	if c, acct, ok := credCharts(evs); ok {
		v.Figs = append(v.Figs, c, acct)
	}

	// Per-source spray-vs-brute classification.
	for ip := range srcSet {
		u, p, a := len(srcUsers[ip]), len(srcPass[ip]), srcAttempts[ip]
		v.Spray = append(v.Spray, sprayRow{Source: ip, Users: u, Passwords: p, Attempts: a, Verdict: sprayVerdict(u, p, a)})
	}
	sort.Slice(v.Spray, func(i, j int) bool {
		if v.Spray[i].Attempts != v.Spray[j].Attempts {
			return v.Spray[i].Attempts > v.Spray[j].Attempts
		}
		return v.Spray[i].Source < v.Spray[j].Source
	})
	if len(v.Spray) > 40 {
		v.Spray = v.Spray[:40]
	}

	// Credential reuse: secrets seen from >= 2 distinct sources.
	for sec, srcs := range secretSrc {
		if len(srcs) >= 2 {
			v.Reuse = append(v.Reuse, reuseRow{Secret: sec, Sources: len(srcs), Services: len(secretSvc[sec]), Count: secretCount[sec]})
		}
	}
	sort.Slice(v.Reuse, func(i, j int) bool {
		if v.Reuse[i].Sources != v.Reuse[j].Sources {
			return v.Reuse[i].Sources > v.Reuse[j].Sources
		}
		return v.Reuse[i].Count > v.Reuse[j].Count
	})
	if len(v.Reuse) > 30 {
		v.Reuse = v.Reuse[:30]
	}
	return v
}

// passClass buckets a password by its character composition.
func passClass(p string) string {
	var lower, upper, digit, sym bool
	for _, r := range p {
		switch {
		case r >= 'a' && r <= 'z':
			lower = true
		case r >= 'A' && r <= 'Z':
			upper = true
		case r >= '0' && r <= '9':
			digit = true
		default:
			sym = true
		}
	}
	switch {
	case digit && !lower && !upper && !sym:
		return "digits only"
	case lower && !upper && !digit && !sym:
		return "lowercase only"
	case sym:
		return "has symbol"
	case lower && upper && digit:
		return "mixed-case + digits"
	case (lower || upper) && digit:
		return "letters + digits"
	default:
		return "letters only"
	}
}

// sprayVerdict labels a source's login pattern by the user/password fan-out.
func sprayVerdict(users, passwords, attempts int) string {
	switch {
	case users >= 5 && passwords <= 2:
		return "password spray"
	case passwords >= 5 && users <= 2:
		return "brute force"
	case users >= 5 && passwords >= 5:
		return "credential stuffing"
	case attempts >= 5:
		return "repeated"
	default:
		return "probe"
	}
}

func slicesFromMap(m map[string]int) []chSlice {
	type kv struct {
		k string
		v int
	}
	items := make([]kv, 0, len(m))
	for k, v := range m {
		items = append(items, kv{k, v})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].v != items[j].v {
			return items[i].v > items[j].v
		}
		return items[i].k < items[j].k
	})
	out := make([]chSlice, 0, len(items))
	for _, it := range items {
		out = append(out, chSlice{Label: it.k, Value: it.v})
	}
	return out
}
