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
	SensorName       string
	DataDir          string
	CaptureMgr       *capture.Manager
	URLCanaries      []config.URLCanary
	Identity         *identity.Identity
	Jitter           *jitter.Jitterer
	TLSRotate        int
	// SensorArchetype is the deployment-default OS archetype (nil
	// for "no default"). A non-empty Listener.Archetype overrides
	// it on the per-listener level.
	SensorArchetype  *archetype.Profile
	Honeynet         *honeynet.Topology
	HoneynetSnapshot handler.HoneynetSnapshot
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
	deps := handler.Deps{
		Identity:     args.Identity,
		Jitter:       args.Jitter,
		DataDir:      args.DataDir,
		URLCanaries:  args.URLCanaries,
		TLSRotate:    args.TLSRotate,
		Archetype:    arch,
		HoneynetView: args.HoneynetSnapshot,
	}
	switch l.Proto {
	case "tcp":
		return newTCP(l, args.SensorName, deps, args.CaptureMgr, sevByID, args.Honeynet)
	case "udp":
		return newUDP(l, args.SensorName, args.Honeynet, args.HoneynetSnapshot)
	}
	return nil, errUnknownProto
}
