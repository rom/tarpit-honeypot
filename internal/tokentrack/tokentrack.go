// Package tokentrack closes the deception loop on minted honey-credentials.
//
// The handlers SERVE synthetic secrets (the webapp DB password, the
// cloud_metadata IAM/OAuth tokens, the vault secret, etc.) and stamp them on
// event meta. On its own that only proves an attacker *read* a fake secret.
// The high-signal event is the secret being *reused* — a synthetic credential
// the sensor handed out later appearing in a captured authentication attempt
// is near-irrefutable proof the attacker (or someone they sold the data to)
// acted on it, the same loop a hosted Canarytoken closes.
//
// Tracker records every served token value and, on each subsequent event,
// checks whether a captured credential matches a previously-served token. A
// match yields a canary:token_used finding carrying both the original mint
// context and the reuse context. It is bounded (a capped set with oldest-first
// eviction) so a flood of distinct served values can't grow it without limit,
// and it only tracks values long enough to be real secrets (short/empty values
// are ignored to avoid matching on "admin"/"password").
package tokentrack

import (
	"sync"
	"time"
)

// minTokenLen ignores trivially-short served values so the tracker doesn't
// match on common words an attacker would guess anyway (we want *our* unique
// secrets, not "root").
const minTokenLen = 8

// defaultCap bounds the number of distinct tracked tokens.
const defaultCap = 50000

// Minted records where/when a token was served.
type Minted struct {
	Value   string
	Handler string
	RuleID  string
	SrcIP   string // the source that was served the token
	First   time.Time
}

// Tracker is concurrency-safe: Record and Check are both called from the bus
// loop, but a future caller could parallelize, so guard with a mutex.
type Tracker struct {
	mu    sync.Mutex
	cap   int
	byVal map[string]Minted
	order []string // insertion order for oldest-first eviction
}

// New builds a Tracker. capN <= 0 uses the default cap.
func New(capN int) *Tracker {
	if capN <= 0 {
		capN = defaultCap
	}
	return &Tracker{cap: capN, byVal: map[string]Minted{}, order: make([]string, 0, 1024)}
}

// Record notes that token value was served in the given context. Short/empty
// values are ignored. Re-serving a known value keeps the original mint context.
func (t *Tracker) Record(value, handler, ruleID, srcIP string, when time.Time) {
	if t == nil || len(value) < minTokenLen {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, ok := t.byVal[value]; ok {
		return
	}
	if len(t.order) >= t.cap {
		// Evict oldest.
		oldest := t.order[0]
		t.order = t.order[1:]
		delete(t.byVal, oldest)
	}
	t.byVal[value] = Minted{Value: value, Handler: handler, RuleID: ruleID, SrcIP: srcIP, First: when}
	t.order = append(t.order, value)
}

// Check reports whether value was previously served as a token, returning the
// mint context. Short values never match.
func (t *Tracker) Check(value string) (Minted, bool) {
	if t == nil || len(value) < minTokenLen {
		return Minted{}, false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	m, ok := t.byVal[value]
	return m, ok
}

// Len returns the number of tracked tokens (for metrics/tests).
func (t *Tracker) Len() int {
	if t == nil {
		return 0
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.byVal)
}
