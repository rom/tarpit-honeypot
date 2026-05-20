package correlate

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

// PersistedState is the JSON-serializable snapshot of the windowed
// detector state. The storyline correlator is intentionally excluded:
// it's a short (30m) in-window aggregation that isn't worth persisting,
// and its nested maps would bloat the file.
type PersistedState struct {
	Scan    map[string]persistedScan  `json:"scan,omitempty"`
	Brute   map[string]persistedBrute `json:"brute,omitempty"`
	Slow    map[string]persistedSlow  `json:"slow,omitempty"`
	Sweep   map[string]persistedSweep `json:"sweep,omitempty"`
	Emitted map[string]time.Time      `json:"emitted,omitempty"`
}

type persistedScan struct {
	Since time.Time `json:"since"`
	Ports []int     `json:"ports"`
}
type persistedBrute struct {
	Since time.Time `json:"since"`
	Count int       `json:"count"`
	Creds []string  `json:"creds"`
}
type persistedSlow struct {
	FirstSeen time.Time         `json:"first_seen"`
	LastSeen  time.Time         `json:"last_seen"`
	Ports     map[int]time.Time `json:"ports"`
}
type persistedSweep struct {
	Since time.Time `json:"since"`
	IPs   []string  `json:"ips"`
}

// Snapshot captures the current detector state. Safe to call concurrently.
func (c *Correlator) Snapshot() PersistedState {
	c.mu.Lock()
	defer c.mu.Unlock()
	ps := PersistedState{
		Scan:    map[string]persistedScan{},
		Brute:   map[string]persistedBrute{},
		Slow:    map[string]persistedSlow{},
		Sweep:   map[string]persistedSweep{},
		Emitted: map[string]time.Time{},
	}
	for ip, st := range c.scan {
		ports := make([]int, 0, len(st.ports))
		for p := range st.ports {
			ports = append(ports, p)
		}
		ps.Scan[ip] = persistedScan{Since: st.since, Ports: ports}
	}
	for k, st := range c.brute {
		creds := make([]string, 0, len(st.creds))
		for cr := range st.creds {
			creds = append(creds, cr)
		}
		ps.Brute[k] = persistedBrute{Since: st.since, Count: st.count, Creds: creds}
	}
	for ip, st := range c.slow {
		ports := make(map[int]time.Time, len(st.ports))
		for p, t := range st.ports {
			ports[p] = t
		}
		ps.Slow[ip] = persistedSlow{FirstSeen: st.firstSeen, LastSeen: st.lastSeen, Ports: ports}
	}
	for ip, st := range c.sweep {
		ips := make([]string, 0, len(st.ips))
		for d := range st.ips {
			ips = append(ips, d)
		}
		ps.Sweep[ip] = persistedSweep{Since: st.since, IPs: ips}
	}
	for k, t := range c.emitted {
		ps.Emitted[k] = t
	}
	return ps
}

// LoadSnapshot replaces the detector state with ps. Used to carry state
// across a hot reload (which builds a fresh Correlator) and to restore
// from disk on startup.
func (c *Correlator) LoadSnapshot(ps PersistedState) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for ip, s := range ps.Scan {
		st := &scanState{since: s.Since, ports: map[int]struct{}{}}
		for _, p := range s.Ports {
			st.ports[p] = struct{}{}
		}
		c.scan[ip] = st
	}
	for k, s := range ps.Brute {
		st := &bruteState{since: s.Since, count: s.Count, creds: map[string]struct{}{}}
		for _, cr := range s.Creds {
			st.creds[cr] = struct{}{}
		}
		c.brute[k] = st
	}
	for ip, s := range ps.Slow {
		st := &slowState{firstSeen: s.FirstSeen, lastSeen: s.LastSeen, ports: map[int]time.Time{}}
		for p, t := range s.Ports {
			st.ports[p] = t
		}
		c.slow[ip] = st
	}
	for ip, s := range ps.Sweep {
		st := &sweepState{since: s.Since, ips: map[string]struct{}{}}
		for _, d := range s.IPs {
			st.ips[d] = struct{}{}
		}
		c.sweep[ip] = st
	}
	for k, t := range ps.Emitted {
		c.emitted[k] = t
	}
}

// Save writes the snapshot to path atomically (temp + rename).
func (c *Correlator) Save(path string) error {
	b, err := json.Marshal(c.Snapshot())
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o640); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// Restore loads state from path. A missing file is not an error (first
// run). Stale entries are pruned by the normal gc on the next Observe.
func (c *Correlator) Restore(path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var ps PersistedState
	if err := json.Unmarshal(b, &ps); err != nil {
		return err
	}
	c.LoadSnapshot(ps)
	return nil
}

// StatePath returns the conventional on-disk location for the correlator
// state inside a data dir.
func StatePath(dataDir string) string { return filepath.Join(dataDir, "correlate-state.json") }
