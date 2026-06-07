package listener

import (
	"context"

	"github.com/rom/tarpit-honeypot/internal/archetype"
	"github.com/rom/tarpit-honeypot/internal/capture"
	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/event"
	"github.com/rom/tarpit-honeypot/internal/honeynet"
	"github.com/rom/tarpit-honeypot/internal/identity"
	"github.com/rom/tarpit-honeypot/internal/jitter"
	"github.com/rom/tarpit-honeypot/internal/listener/handler"
	"github.com/rom/tarpit-honeypot/internal/sessionrec"
)

// Listener is something that emits events to the bus until ctx is cancelled.
type Listener interface {
	ID() string
	Start(ctx context.Context, bus chan<- *event.Event) error
}

// BuildArgs collects the cross-cutting dependencies a listener needs at
// construction time. Keeps Build's signature stable as we add deployment
// identity, jitter, retry-queue stats, etc.
type BuildArgs struct {
	SensorName string
	// Binds is the concrete set of "host:port" addresses this listener should
	// bind (resolved from the listener's bind + sensor.listen_addresses /
	// interfaces). One logical listener can own several sockets — e.g. the same
	// SSH decoy on three server IPs — all feeding one handler; the destination
	// IP is still recorded per connection. Empty falls back to the listener's
	// own cfg.Bind (the single-socket default).
	Binds       []string
	DataDir     string
	CaptureMgr  *capture.Manager
	URLCanaries []config.URLCanary
	Identity    *identity.Identity
	Jitter      *jitter.Jitterer
	TLSRotate   int
	// SensorArchetype is the deployment-default OS archetype (nil
	// for "no default"). A non-empty Listener.Archetype overrides
	// it on the per-listener level.
	SensorArchetype  *archetype.Profile
	Honeynet         *honeynet.Topology
	HoneynetSnapshot handler.HoneynetSnapshot
	// VulnEmulation is the sensor-level default for vulnerable-banner
	// emulation. A non-nil Listener.VulnEmulation overrides it.
	VulnEmulation bool
	// SessionRec records interactive shell sessions (nil = disabled).
	SessionRec *sessionrec.Store
	// SSHKexExtended unlocks best-effort SSH key-exchange capture beyond
	// the client KEXINIT/HASSH (interaction.ssh_kex_depth:
	// extended_experimental).
	SSHKexExtended bool
	// MaxUploadBytes caps how much of an uploaded file handlers capture for
	// retention + classification (sensor.payloads.max_upload_kb).
	MaxUploadBytes int
}

func Build(l config.Listener, args BuildArgs) (Listener, error) {
	sevByID := map[string]event.Severity{}
	for _, c := range args.URLCanaries {
		if s, err := event.ParseSeverity(c.Severity); err == nil {
			sevByID[c.ID] = s
		}
	}
	arch := args.SensorArchetype
	if l.Archetype != "" {
		if p := archetype.Lookup(l.Archetype); p != nil {
			arch = p
		}
	}
	vuln := args.VulnEmulation
	if l.VulnEmulation != nil {
		vuln = *l.VulnEmulation
	}
	deps := handler.Deps{
		Identity:       args.Identity,
		Jitter:         args.Jitter,
		DataDir:        args.DataDir,
		URLCanaries:    args.URLCanaries,
		TLSRotate:      args.TLSRotate,
		Archetype:      arch,
		AcceptCreds:    l.AcceptCreds,
		HoneynetView:   args.HoneynetSnapshot,
		VulnEmulation:  vuln,
		Script:         l.Script,
		Scripted:       l.Scripted,
		TLSIntercept:   l.TLSIntercept,
		SessionRec:     args.SessionRec,
		SSHKexExtended: args.SSHKexExtended,
		MaxUploadBytes: args.MaxUploadBytes,
	}
	switch l.Proto {
	case "tcp":
		return newTCP(l, args.SensorName, deps, args.CaptureMgr, sevByID, args.Honeynet, args.Binds)
	case "udp":
		return newUDP(l, args.SensorName, args.Honeynet, args.HoneynetSnapshot, deps, args.Binds)
	}
	return nil, errUnknownProto
}
