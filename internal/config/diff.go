package config

import (
	"fmt"
	"reflect"
	"sort"
	"strings"
)

// Diff is what changes between two configs and whether each change can be
// applied via SIGHUP hot-reload or requires a full restart.
type Diff struct {
	HotReloadable []Change
	RestartNeeded []Change
}

// Change is a single human-readable diff line.
type Change struct {
	Section string // listeners | channels | routes | canaries | ...
	Action  string // added | removed | modified
	ID      string // entity id (or "" for top-level toggles)
	Detail  string // free-form text explaining what changed
}

// String renders a change in `[section] <action> <id>: <detail>` form.
func (c Change) String() string {
	prefix := fmt.Sprintf("[%s] %s", c.Section, c.Action)
	if c.ID != "" {
		prefix += " " + c.ID
	}
	if c.Detail != "" {
		return prefix + ": " + c.Detail
	}
	return prefix
}

// HasChanges reports whether the diff is non-empty.
func (d Diff) HasChanges() bool {
	return len(d.HotReloadable) > 0 || len(d.RestartNeeded) > 0
}

// DiffConfigs compares two configs and classifies each change as
// hot-reloadable or restart-required. Top-level toggles that affect the
// listener set (listeners, dns, sniffer.enabled, ui, sensor.* basics)
// require restart; everything else (channels, routes, allowlist, dedup,
// correlator, canaries, url/dns canary lists) can hot-reload.
func DiffConfigs(old, new *Config) Diff {
	var d Diff

	// Sensor-level fields that need restart.
	if old.Sensor.Name != new.Sensor.Name {
		d.RestartNeeded = append(d.RestartNeeded, Change{
			Section: "sensor", Action: "modified",
			Detail: fmt.Sprintf("name: %q -> %q", old.Sensor.Name, new.Sensor.Name),
		})
	}
	if old.Sensor.DataDir != new.Sensor.DataDir {
		d.RestartNeeded = append(d.RestartNeeded, Change{
			Section: "sensor", Action: "modified",
			Detail: fmt.Sprintf("data_dir: %q -> %q", old.Sensor.DataDir, new.Sensor.DataDir),
		})
	}
	if old.Sensor.DropUser != new.Sensor.DropUser || old.Sensor.DropGroup != new.Sensor.DropGroup {
		d.RestartNeeded = append(d.RestartNeeded, Change{
			Section: "sensor", Action: "modified",
			Detail: fmt.Sprintf("drop_user/group: %s:%s -> %s:%s",
				old.Sensor.DropUser, old.Sensor.DropGroup, new.Sensor.DropUser, new.Sensor.DropGroup),
		})
	}
	if !reflect.DeepEqual(old.UI, new.UI) {
		d.RestartNeeded = append(d.RestartNeeded, Change{
			Section: "ui", Action: "modified",
			Detail: "web UI settings changed",
		})
	}

	// Listeners: any add/remove/modify needs restart in the current model.
	// Hot-reload of listeners can land later; for now report cleanly.
	d.RestartNeeded = append(d.RestartNeeded, listenerChanges(old.Listeners, new.Listeners)...)

	// DNS listener config: any change requires restart (it owns a socket).
	if old.DNS != new.DNS {
		d.RestartNeeded = append(d.RestartNeeded, Change{
			Section: "dns", Action: "modified",
			Detail: fmt.Sprintf("enabled=%v bind=%q -> enabled=%v bind=%q",
				old.DNS.Enabled, old.DNS.Bind, new.DNS.Enabled, new.DNS.Bind),
		})
	}

	// Sniffer: enable/disable + interface + tcp_scan toggle need restart
	// (the sockets + trackers are set up once at sniffer construction).
	if old.Sniffer.Enabled != new.Sniffer.Enabled ||
		old.Sniffer.Interface != new.Sniffer.Interface ||
		old.Sniffer.TCPScan.Enabled != new.Sniffer.TCPScan.Enabled {
		d.RestartNeeded = append(d.RestartNeeded, Change{
			Section: "sniffer", Action: "modified",
			Detail: fmt.Sprintf("enabled=%v iface=%q tcp_scan=%v -> enabled=%v iface=%q tcp_scan=%v",
				old.Sniffer.Enabled, old.Sniffer.Interface, old.Sniffer.TCPScan.Enabled,
				new.Sniffer.Enabled, new.Sniffer.Interface, new.Sniffer.TCPScan.Enabled),
		})
	}

	// Hot-reloadable: channels, routes, allowlist, dedup, correlator
	// thresholds, canaries (the watcher restarts its file watches), url
	// canaries, dns canaries (the running listener picks up the new list).
	d.HotReloadable = append(d.HotReloadable, channelChanges(old.Channels, new.Channels)...)
	d.HotReloadable = append(d.HotReloadable, routeChanges(old.Routes, new.Routes)...)
	if !reflect.DeepEqual(old.Allowlist, new.Allowlist) {
		d.HotReloadable = append(d.HotReloadable, Change{
			Section: "allowlist", Action: "modified",
			Detail: fmt.Sprintf("%d entries -> %d entries", len(old.Allowlist), len(new.Allowlist)),
		})
	}
	if old.Dedup != new.Dedup {
		d.HotReloadable = append(d.HotReloadable, Change{
			Section: "dedup", Action: "modified",
			Detail: fmt.Sprintf("default_window: %s -> %s",
				old.Dedup.DefaultWindow, new.Dedup.DefaultWindow),
		})
	}
	if old.Correlate != new.Correlate {
		d.HotReloadable = append(d.HotReloadable, Change{
			Section: "correlate", Action: "modified",
			Detail: "correlator thresholds changed",
		})
	}
	d.HotReloadable = append(d.HotReloadable, listChanges("canaries", canaryIDs(old.Canaries), canaryIDs(new.Canaries))...)
	d.HotReloadable = append(d.HotReloadable, listChanges("url_canaries", urlCanaryIDs(old.URLCanaries), urlCanaryIDs(new.URLCanaries))...)
	d.HotReloadable = append(d.HotReloadable, listChanges("dns_canaries", dnsCanaryIDs(old.DNSCanaries), dnsCanaryIDs(new.DNSCanaries))...)

	return d
}

func listenerChanges(old, new []Listener) []Change {
	oldByID := map[string]Listener{}
	for _, l := range old {
		oldByID[l.ID] = l
	}
	newByID := map[string]Listener{}
	for _, l := range new {
		newByID[l.ID] = l
	}
	var out []Change
	var ids []string
	for id := range oldByID {
		ids = append(ids, id)
	}
	for id := range newByID {
		if _, ok := oldByID[id]; !ok {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	for _, id := range ids {
		oldL, oldOk := oldByID[id]
		newL, newOk := newByID[id]
		switch {
		case !oldOk:
			out = append(out, Change{Section: "listeners", Action: "added", ID: id,
				Detail: fmt.Sprintf("%s %s mode=%s handler=%s", newL.Proto, newL.Bind, newL.Mode, newL.Handler)})
		case !newOk:
			out = append(out, Change{Section: "listeners", Action: "removed", ID: id,
				Detail: fmt.Sprintf("was %s %s", oldL.Proto, oldL.Bind)})
		case !reflect.DeepEqual(oldL, newL):
			diffs := []string{}
			if oldL.Bind != newL.Bind {
				diffs = append(diffs, fmt.Sprintf("bind %s -> %s", oldL.Bind, newL.Bind))
			}
			if oldL.Proto != newL.Proto {
				diffs = append(diffs, fmt.Sprintf("proto %s -> %s", oldL.Proto, newL.Proto))
			}
			if oldL.Mode != newL.Mode {
				diffs = append(diffs, fmt.Sprintf("mode %s -> %s", oldL.Mode, newL.Mode))
			}
			if oldL.Handler != newL.Handler {
				diffs = append(diffs, fmt.Sprintf("handler %s -> %s", oldL.Handler, newL.Handler))
			}
			if oldL.Severity != newL.Severity {
				diffs = append(diffs, fmt.Sprintf("severity %s -> %s", oldL.Severity, newL.Severity))
			}
			if oldL.Capture != newL.Capture {
				diffs = append(diffs, fmt.Sprintf("capture %v -> %v", oldL.Capture, newL.Capture))
			}
			if len(diffs) == 0 {
				diffs = append(diffs, "settings changed")
			}
			out = append(out, Change{Section: "listeners", Action: "modified", ID: id,
				Detail: strings.Join(diffs, ", ")})
		}
	}
	return out
}

func channelChanges(old, new []Channel) []Change {
	oldByID := map[string]Channel{}
	for _, c := range old {
		oldByID[c.ID] = c
	}
	newByID := map[string]Channel{}
	for _, c := range new {
		newByID[c.ID] = c
	}
	var out []Change
	var ids []string
	for id := range oldByID {
		ids = append(ids, id)
	}
	for id := range newByID {
		if _, ok := oldByID[id]; !ok {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	for _, id := range ids {
		oldC, oldOk := oldByID[id]
		newC, newOk := newByID[id]
		switch {
		case !oldOk:
			out = append(out, Change{Section: "channels", Action: "added", ID: id, Detail: newC.Type})
		case !newOk:
			out = append(out, Change{Section: "channels", Action: "removed", ID: id, Detail: oldC.Type})
		case !reflect.DeepEqual(oldC, newC):
			out = append(out, Change{Section: "channels", Action: "modified", ID: id, Detail: ""})
		}
	}
	return out
}

func routeChanges(old, new []Route) []Change {
	if reflect.DeepEqual(old, new) {
		return nil
	}
	return []Change{{Section: "routes", Action: "modified",
		Detail: fmt.Sprintf("%d routes -> %d routes", len(old), len(new))}}
}

func listChanges(section string, oldIDs, newIDs map[string]bool) []Change {
	var out []Change
	for id := range oldIDs {
		if !newIDs[id] {
			out = append(out, Change{Section: section, Action: "removed", ID: id})
		}
	}
	for id := range newIDs {
		if !oldIDs[id] {
			out = append(out, Change{Section: section, Action: "added", ID: id})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Section != out[j].Section {
			return out[i].Section < out[j].Section
		}
		return out[i].ID < out[j].ID
	})
	return out
}

func canaryIDs(cs []Canary) map[string]bool {
	out := map[string]bool{}
	for _, c := range cs {
		out[c.ID] = true
	}
	return out
}

func urlCanaryIDs(cs []URLCanary) map[string]bool {
	out := map[string]bool{}
	for _, c := range cs {
		out[c.ID] = true
	}
	return out
}

func dnsCanaryIDs(cs []DNSCanary) map[string]bool {
	out := map[string]bool{}
	for _, c := range cs {
		out[c.ID] = true
	}
	return out
}
