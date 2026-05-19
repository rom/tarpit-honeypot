package format

import (
	"encoding/json"
	"strings"

	"github.com/rom/tarpit-honeypot/internal/event"
)

type ocsfF struct{}

func (o *ocsfF) Name() string        { return "ocsf" }
func (o *ocsfF) ContentType() string { return "application/json" }

// OCSF (Open Cybersecurity Schema Framework) v1.x emits our events as
// "Network Activity" (class_uid=4001) JSON records. This is the schema
// AWS Security Lake, Snowflake, and the new generation of cloud SIEMs
// consume natively. Required fields per OCSF v1.0:
//
//   class_uid, category_uid, activity_id, type_uid,
//   severity_id, time, metadata
//
// We additionally populate src_endpoint, dst_endpoint, connection_info,
// observables, and unmapped (the catch-all for handler/honeynet meta).
func (o *ocsfF) Format(ev *event.Event) ([]byte, error) {
	doc := map[string]any{
		"class_uid":    4001, // Network Activity
		"category_uid": 4,    // Network Activity category
		"activity_id":  1,    // Open
		"type_uid":     400101,
		"severity_id":  ocsfSeverity(ev.Severity),
		"severity":     ev.Severity.String(),
		"time":         ev.Time.UTC().UnixMilli(),
		"metadata": map[string]any{
			"version": "1.0.0",
			"product": map[string]any{
				"vendor_name": Vendor,
				"name":        Product,
				"version":     ProductVN,
			},
			"event_code": ev.RuleID,
			"uid":        ev.ID,
		},
		"observables": observables(ev),
	}
	if ev.Sensor != "" {
		doc["device"] = map[string]any{"hostname": ev.Sensor}
	}
	if ev.Source.IP != "" {
		ep := map[string]any{"ip": ev.Source.IP}
		if ev.Source.Port > 0 {
			ep["port"] = ev.Source.Port
		}
		doc["src_endpoint"] = ep
	}
	if ev.Dest.IP != "" {
		ep := map[string]any{"ip": ev.Dest.IP}
		if ev.Dest.Port > 0 {
			ep["port"] = ev.Dest.Port
		}
		doc["dst_endpoint"] = ep
	}
	if ev.Proto != "" {
		doc["connection_info"] = map[string]any{
			"protocol_name": strings.ToUpper(ev.Proto),
		}
	}
	// Unmapped catches handler / honeynet / fingerprint meta keys that
	// don't have a dedicated OCSF slot.
	if len(ev.Meta) > 0 {
		doc["unmapped"] = ev.Meta
	}
	return json.Marshal(doc)
}

// ocsfSeverity maps tarpit-honeypot severities to OCSF's 1-6 scale
// (Informational/Low/Medium/High/Critical/Fatal).
func ocsfSeverity(s event.Severity) int {
	switch s {
	case event.SeverityLow:
		return 2
	case event.SeverityMedium:
		return 3
	case event.SeverityHigh:
		return 4
	case event.SeverityCritical:
		return 5
	}
	return 1
}

// observables surfaces the source and destination IPs as first-class
// observable objects so downstream OCSF consumers can pivot on them
// without parsing the endpoint structs.
func observables(ev *event.Event) []map[string]any {
	var out []map[string]any
	if ev.Source.IP != "" {
		out = append(out, map[string]any{
			"name":    "src_endpoint.ip",
			"type":    "IP Address",
			"type_id": 2,
			"value":   ev.Source.IP,
		})
	}
	if ev.Dest.IP != "" {
		out = append(out, map[string]any{
			"name":    "dst_endpoint.ip",
			"type":    "IP Address",
			"type_id": 2,
			"value":   ev.Dest.IP,
		})
	}
	return out
}
