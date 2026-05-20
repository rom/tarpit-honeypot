package honeynet

import "context"

// LLDPCfg controls the per-honeynet LLDP / CDP advertiser. When
// enabled, the sensor periodically transmits LLDP frames (always)
// and optionally CDP frames (Cisco discovery — useful when
// the deception surface includes Cisco-flavored archetypes) on the
// named interface, advertising each honeynet host's MAC + hostname
// + archetype-derived system description as a believable L2
// neighbor.
//
// LLDP/CDP advertising requires raw L2 sockets (AF_PACKET) and
// CAP_NET_RAW. The non-Linux build returns an error from
// StartLLDPResponder so the operator gets a clean diagnostic
// instead of a silent no-op.
type LLDPCfg struct {
	Enabled    bool
	Interface  string
	Interval   int // seconds; 0 -> default 30
	IncludeCDP bool
}

// StartLLDPResponder is the public entry point. The Linux variant
// drives the AF_PACKET socket loop; the non-Linux build returns a
// "platform unsupported" error.
func StartLLDPResponder(ctx context.Context, cfg LLDPCfg, topo *Topology) error {
	return startLLDPResponder(ctx, cfg, topo)
}
