// Package devices maintains a learned inventory of hosts the sensor
// has observed on the network — from DHCP traffic, ARP, and the source
// addresses of connections it handles. It powers two operator
// features:
//
//   - "new device" alerts: when a host appears that is neither in the
//     operator-supplied allow-list nor already in the learned
//     baseline, the sensor emits a device:new event. This turns the
//     honeypot into a passive rogue-device detector for the segment
//     it sits on.
//
//   - the list-devices subcommand: dumps the learned inventory
//     (IP / MAC / hostname / vendor / first+last seen / source) so an
//     operator can review what's on the wire and snapshot a baseline.
//
// The registry persists to <data_dir>/devices.json so the baseline
// survives restarts. It is safe for concurrent use.
package devices

import (
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Source records how a device first became known.
type Source string

const (
	SourceDHCP      Source = "dhcp"
	SourceARP       Source = "arp"
	SourceConn      Source = "conn"      // source IP of a handled connection
	SourceBroadcast Source = "broadcast" // mDNS / SSDP / LLMNR / NBNS sender
	SourceManual    Source = "manual"    // operator-provided
)

// Device is one learned host. Beyond the first-seen identity it accumulates
// knowledge over time: the sensor services/ports the host touched and
// free-form attributes (client fingerprints, OS/tool hints) that other
// listeners and sensor parts contribute.
type Device struct {
	IP        string            `json:"ip,omitempty"`
	MAC       string            `json:"mac,omitempty"`
	Hostname  string            `json:"hostname,omitempty"`
	Vendor    string            `json:"vendor,omitempty"` // from MAC OUI
	Source    Source            `json:"source"`           // first-seen source
	FirstSeen time.Time         `json:"first_seen"`
	LastSeen  time.Time         `json:"last_seen"`
	Count     int               `json:"count"`              // observation count
	Allowed   bool              `json:"allowed,omitempty"`  // operator-whitelisted (persisted)
	Ports     []int             `json:"ports,omitempty"`    // sensor ports the host hit
	Services  []string          `json:"services,omitempty"` // handlers the host interacted with
	Attrs     map[string]string `json:"attrs,omitempty"`    // learned attributes (ja3/hassh/ua/os/tools/…)
}

// Observation is the input to Observe — whatever a producer learned
// about a host in one event. Empty fields are ignored.
type Observation struct {
	IP       string
	MAC      string
	Hostname string
	Source   Source
	Time     time.Time
	// Enrichment (all optional): the sensor port the host hit, the handler
	// it interacted with, and free-form learned attributes.
	Port    int
	Service string
	Attrs   map[string]string
}

// bounds on per-device accumulated knowledge.
const (
	maxDevicePorts    = 64
	maxDeviceServices = 32
	maxDeviceAttrs    = 32
)

// Registry is the thread-safe device inventory.
type Registry struct {
	mu             sync.Mutex
	byKey          map[string]*Device // key = MAC if known, else IP
	allowIP        map[string]bool
	allowMAC       map[string]bool
	allowCIDR      []netip.Prefix
	path           string
	learn          bool
	dirty          bool
	loadedExisting bool
}

// Config configures a Registry.
type Config struct {
	// DataDir is where devices.json is persisted (empty = no persistence).
	DataDir string
	// Allow is the operator allow-list of known IPs, CIDRs, and MACs.
	// A device matching any entry never raises a device:new alert.
	Allow []string
	// Learn, when true, treats the FIRST observation of every device
	// as the baseline (no alert); subsequent never-before-seen devices
	// DO alert. When false, every non-allow-listed device alerts on
	// first sight (strict allow-list mode).
	Learn bool
}

// New builds a Registry, loading any persisted inventory.
func New(cfg Config) *Registry {
	r := &Registry{
		byKey:    map[string]*Device{},
		allowIP:  map[string]bool{},
		allowMAC: map[string]bool{},
		learn:    cfg.Learn,
	}
	for _, a := range cfg.Allow {
		a = strings.TrimSpace(a)
		if a == "" {
			continue
		}
		if p, err := netip.ParsePrefix(a); err == nil {
			r.allowCIDR = append(r.allowCIDR, p)
			continue
		}
		if _, err := netip.ParseAddr(a); err == nil {
			r.allowIP[a] = true
			continue
		}
		// Otherwise treat as a MAC (normalized lower, colon-separated).
		r.allowMAC[normalizeMAC(a)] = true
	}
	if cfg.DataDir != "" {
		r.path = filepath.Join(cfg.DataDir, "devices.json")
		r.load()
	}
	return r
}

// ObserveResult is what Observe reports back: the resulting device, whether
// it warrants a device:new alert, and any identity fields that changed value
// on an already-known device (an IP/MAC rebind or hostname change — a
// rogue-device / ARP-spoofing signal).
type ObserveResult struct {
	Device  Device
	New     bool
	Changed []string // e.g. "ip 10.0.0.5 -> 10.0.0.9"
}

// Observe records a host observation. It returns an ObserveResult: the
// resulting Device, whether it should raise a device:new alert (true only
// the first time a non-allow-listed device is seen, and only when not
// establishing the learn-mode baseline), and any changed identity fields.
func (r *Registry) Observe(o Observation) ObserveResult {
	if o.IP == "" && o.MAC == "" {
		return ObserveResult{}
	}
	now := o.Time
	if now.IsZero() {
		now = time.Now().UTC()
	}
	mac := normalizeMAC(o.MAC)

	r.mu.Lock()
	defer r.mu.Unlock()

	key := mac
	if key == "" {
		key = o.IP
	}
	d, existed := r.byKey[key]
	if !existed && mac != "" && o.IP != "" {
		// A prior IP-only record may exist; promote it to the MAC key.
		if prev, ok := r.byKey[o.IP]; ok {
			d, existed = prev, true
			delete(r.byKey, o.IP)
			r.byKey[key] = d
		}
	}
	if !existed {
		d = &Device{
			Source:    o.Source,
			FirstSeen: now,
		}
		r.byKey[key] = d
	}
	// Detect identity rebinds on an already-known device (before we
	// overwrite the stored values).
	var changed []string
	if existed {
		if o.IP != "" && d.IP != "" && d.IP != o.IP {
			changed = append(changed, "ip "+d.IP+" -> "+o.IP)
		}
		if mac != "" && d.MAC != "" && d.MAC != mac {
			changed = append(changed, "mac "+d.MAC+" -> "+mac)
		}
		if o.Hostname != "" && d.Hostname != "" && d.Hostname != o.Hostname {
			changed = append(changed, "hostname "+d.Hostname+" -> "+o.Hostname)
		}
	}
	if o.IP != "" {
		d.IP = o.IP
	}
	if mac != "" {
		d.MAC = mac
		if v := VendorForMAC(mac); v != "" {
			d.Vendor = v
		}
	}
	if o.Hostname != "" {
		d.Hostname = o.Hostname
	}
	if o.Port > 0 {
		d.Ports = addInt(d.Ports, o.Port, maxDevicePorts)
	}
	if o.Service != "" {
		d.Services = addStr(d.Services, o.Service, maxDeviceServices)
	}
	for k, v := range o.Attrs {
		if k == "" || v == "" {
			continue
		}
		if d.Attrs == nil {
			d.Attrs = map[string]string{}
		}
		if _, ok := d.Attrs[k]; !ok && len(d.Attrs) >= maxDeviceAttrs {
			continue
		}
		d.Attrs[k] = v
	}
	d.LastSeen = now
	d.Count++
	r.dirty = true

	alert := false
	if !existed && !r.isAllowed(d) {
		// First sighting of a non-allow-listed device.
		if r.learn && r.baselineEstablishing() {
			// During the very first run, treat the initial population
			// as baseline. We approximate "establishing" as: this is
			// not the only device (i.e. we already learned others in
			// this process) — see baselineEstablishing.
			alert = false
		} else {
			alert = true
		}
	}
	return ObserveResult{Device: *d, New: alert, Changed: changed}
}

// baselineEstablishing is a heuristic: in learn mode, the very first
// device observed in a fresh (empty-on-disk) registry seeds the
// baseline silently; everything after alerts. Called with r.mu held.
func (r *Registry) baselineEstablishing() bool {
	// If we loaded a persisted baseline, we're past establishment.
	return !r.loadedExisting && len(r.byKey) <= 1
}

// isAllowed reports whether the device matches the operator allow-list.
// Called with r.mu held.
func (r *Registry) isAllowed(d *Device) bool {
	if d.Allowed { // operator-whitelisted at runtime (persisted)
		return true
	}
	if d.MAC != "" && r.allowMAC[d.MAC] {
		return true
	}
	if d.IP != "" {
		if r.allowIP[d.IP] {
			return true
		}
		if len(r.allowCIDR) > 0 {
			if a, err := netip.ParseAddr(d.IP); err == nil {
				for _, p := range r.allowCIDR {
					if p.Contains(a) {
						return true
					}
				}
			}
		}
	}
	return false
}

// IsAllowed reports whether a device matches the operator allow-list.
// Safe for external callers (takes r.mu); used by the web UI hosts view.
func (r *Registry) IsAllowed(d Device) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.isAllowed(&d)
}

// Delete removes a device by its registry key (its MAC if known, else its
// IP). Returns whether a device was removed. Used by the web UI's
// device-delete action.
func (r *Registry) Delete(key string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, k := range []string{key, normalizeMAC(key)} {
		if _, ok := r.byKey[k]; ok {
			delete(r.byKey, k)
			r.dirty = true
			return true
		}
	}
	return false
}

// Allow whitelists a device by its registry key — it stops raising
// device:new and is persisted (Device.Allowed) so the whitelist survives a
// restart. Returns whether the device was found. Used by the web UI's
// whitelist action.
func (r *Registry) Allow(key string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, k := range []string{key, normalizeMAC(key)} {
		if d, ok := r.byKey[k]; ok {
			d.Allowed = true
			r.dirty = true
			return true
		}
	}
	return false
}

// addInt appends v to xs (deduped, sorted) up to a cap.
func addInt(xs []int, v, max int) []int {
	for _, x := range xs {
		if x == v {
			return xs
		}
	}
	if len(xs) >= max {
		return xs
	}
	xs = append(xs, v)
	sort.Ints(xs)
	return xs
}

// addStr appends s to xs (deduped) up to a cap.
func addStr(xs []string, s string, max int) []string {
	for _, x := range xs {
		if x == s {
			return xs
		}
	}
	if len(xs) >= max {
		return xs
	}
	return append(xs, s)
}

// List returns a snapshot of all known devices, sorted by IP then MAC.
func (r *Registry) List() []Device {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]Device, 0, len(r.byKey))
	for _, d := range r.byKey {
		out = append(out, *d)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].IP != out[j].IP {
			return lessIP(out[i].IP, out[j].IP)
		}
		return out[i].MAC < out[j].MAC
	})
	return out
}

// Save persists the inventory to <data_dir>/devices.json if a path is
// configured and the inventory changed since the last save.
func (r *Registry) Save() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.path == "" || !r.dirty {
		return nil
	}
	devs := make([]*Device, 0, len(r.byKey))
	for _, d := range r.byKey {
		devs = append(devs, d)
	}
	b, err := json.MarshalIndent(devs, "", "  ")
	if err != nil {
		return err
	}
	tmp := r.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o640); err != nil {
		return err
	}
	if err := os.Rename(tmp, r.path); err != nil {
		return err
	}
	r.dirty = false
	return nil
}

func (r *Registry) load() {
	b, err := os.ReadFile(r.path)
	if err != nil {
		return
	}
	var devs []*Device
	if err := json.Unmarshal(b, &devs); err != nil {
		return
	}
	for _, d := range devs {
		key := d.MAC
		if key == "" {
			key = d.IP
		}
		if key != "" {
			r.byKey[key] = d
		}
	}
	r.loadedExisting = len(r.byKey) > 0
}
