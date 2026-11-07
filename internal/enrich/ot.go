package enrich

import (
	"github.com/rom/tarpit-honeypot/internal/event"
	"github.com/rom/tarpit-honeypot/internal/otclass"
)

// decorateOTClass stamps the unified operational-technology signal on any event
// that reached an OT handler — ICS/SCADA, building automation (BAS/BMS), or
// medtech. It runs BEFORE the GeoIP/reputation path (which early-returns on
// private sources) because OT lives on RFC1918 segments: an OT probe from
// 10.x / 192.168.x must still be marked OT. It sets:
//
//	ot        = true                (a single flag SIEM rules key on)
//	ot_class  = "ics" | "bas" | "medtech"
//	targeting = "ics-ot" | "healthcare"   (if not already set; drives ot-recon)
//	labels   += "meta:ot"           (the umbrella badge; /events?label=ot filter)
//
// For public sources the recognition pipeline rebuilds labels from scratch and
// re-adds meta:ot from the ot flag, so this is not duplicated; for private
// sources (recognition skipped) the label set here is what survives.
func decorateOTClass(ev *event.Event) {
	if ev == nil || ev.Handler == "" {
		return
	}
	c := otclass.Of(ev.Handler)
	if c == otclass.None {
		return
	}
	if ev.Meta == nil {
		ev.Meta = map[string]any{}
	}
	ev.Meta["ot"] = true
	ev.Meta["ot_class"] = string(c)
	if metaString(ev.Meta, "targeting") == "" {
		if t := otclass.Targeting(ev.Handler); t != "" {
			ev.Meta["targeting"] = t
		}
	}
	labels := appendUniqueTool(existingTools(ev.Meta["labels"]), "meta:ot")
	ev.Meta["labels"] = labels
}
