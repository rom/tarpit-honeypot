package cli

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/identity"
	"github.com/rom/tarpit-honeypot/internal/jitter"
	"github.com/rom/tarpit-honeypot/internal/listener/handler"
	"github.com/rom/tarpit-honeypot/internal/store"
)

// cmdReplay re-runs a recorded attack request back through the protocol
// handler offline (no socket), printing the resulting anomalies / CVE hits /
// captured meta. It is a deterministic regression + tuning harness:
//
//	--event <id>   replay the bytes the sensor captured for an event back
//	               through that event's handler, and report whether the
//	               recomputed detection DIFFERS from what was stored.
//	--handler X    feed arbitrary bytes (--file / stdin) to handler X.
//
// The handler never touches a real socket or executes anything; this only
// exercises the parse + detect path.
func cmdReplay(args []string) error {
	fs := flag.NewFlagSet("replay", flag.ContinueOnError)
	cfgPath := fs.String("c", "/etc/tarpit-honeypot/config.yaml", "path to config file")
	handlerName := fs.String("handler", "", "protocol handler to drive (e.g. http, ssh, redis); inferred from --event if unset")
	eventID := fs.String("event", "", "replay the payload the sensor captured for this event id (from the store)")
	file := fs.String("file", "", "read request bytes from this file (\"-\" or unset with no --event = stdin)")
	udp := fs.Bool("udp", false, "treat the handler as UDP (datagram) instead of TCP")
	vuln := fs.Bool("vuln", false, "enable vulnerable-banner emulation for the replay")
	asJSON := fs.Bool("json", true, "emit the result as JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}

	var input []byte
	var stored *storedDetect
	switch {
	case *eventID != "":
		ev, payload, err := loadEventPayload(cfg.Sensor.DataDir, *eventID)
		if err != nil {
			return err
		}
		input = payload
		if *handlerName == "" {
			*handlerName = ev.Handler
		}
		stored = &storedDetect{anomalies: ev.Anomalies, rule: ev.RuleID}
	case *file != "" && *file != "-":
		if input, err = os.ReadFile(*file); err != nil {
			return err
		}
	default:
		if input, err = io.ReadAll(os.Stdin); err != nil {
			return err
		}
	}
	if *handlerName == "" {
		return fmt.Errorf("replay: --handler is required (or use --event to infer it)")
	}

	deps := handler.Deps{
		Identity:      identity.New(cfg.Sensor.DeploymentID),
		Jitter:        jitter.New(0, 0),
		DataDir:       cfg.Sensor.DataDir,
		VulnEmulation: *vuln,
	}
	lcfg := config.Listener{Handler: *handlerName, Mode: "banner"}

	res, err := driveHandler(*handlerName, *udp, input, deps, lcfg)
	if err != nil {
		return err
	}

	anoms, _ := res.Meta["anomalies"].([]string)
	out := map[string]any{
		"handler":     *handlerName,
		"input_bytes": len(input),
		"banner_sent": clipForReplay(res.BannerSent),
		"anomalies":   anoms,
		"cve_hits":    res.CVEHits,
		"canary_hits": res.CanaryHits,
		"meta":        res.Meta,
	}
	if stored != nil {
		out["regression"] = compareDetect(stored, anoms, res.CVEHits)
	}

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(out)
	}
	fmt.Printf("handler=%s input=%dB anomalies=%v cve=%v\n", *handlerName, len(input), anoms, res.CVEHits)
	if stored != nil {
		fmt.Println(out["regression"])
	}
	return nil
}

type storedDetect struct {
	anomalies []string
	rule      string
}

// driveHandler runs the named handler against the recorded bytes with no real
// socket: a TCP handler gets a one-shot net.Conn that reads the bytes and
// discards writes; a UDP handler gets the bytes as one datagram.
func driveHandler(name string, udp bool, input []byte, deps handler.Deps, lcfg config.Listener) (handler.Result, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if udp {
		h, err := handler.GetUDP(name, deps)
		if err != nil {
			return handler.Result{}, err
		}
		return h.Handle(ctx, input, fakeAddr{}, nil, lcfg)
	}
	h, err := handler.Get(name, deps)
	if err != nil {
		// Fall back to UDP in case the operator forgot --udp.
		if hu, uerr := handler.GetUDP(name, deps); uerr == nil {
			return hu.Handle(ctx, input, fakeAddr{}, nil, lcfg)
		}
		return handler.Result{}, err
	}
	return h.Handle(ctx, newReplayConn(input), lcfg)
}

// loadEventPayload fetches an event + its captured request bytes from the store.
func loadEventPayload(dataDir, id string) (*event_, []byte, error) {
	st, err := store.Open(dataDir, 0)
	if err != nil {
		return nil, nil, err
	}
	defer st.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ev, err := st.Get(ctx, id)
	if err != nil {
		return nil, nil, err
	}
	if ev == nil {
		return nil, nil, fmt.Errorf("replay: event %q not found", id)
	}
	if ev.PayloadBase64 == "" {
		return nil, nil, fmt.Errorf("replay: event %q has no captured payload to replay", id)
	}
	raw, err := base64.StdEncoding.DecodeString(ev.PayloadBase64)
	if err != nil {
		return nil, nil, fmt.Errorf("replay: decode payload: %w", err)
	}
	return &event_{Handler: ev.Handler, Anomalies: ev.Anomalies, RuleID: ev.RuleID}, raw, nil
}

// event_ is the minimal slice of event.Event replay needs (avoids leaking the
// full type through this file's helpers).
type event_ struct {
	Handler   string
	Anomalies []string
	RuleID    string
}

func compareDetect(stored *storedDetect, anoms, cve []string) string {
	add, drop := diffSets(stored.anomalies, anoms)
	if len(add) == 0 && len(drop) == 0 {
		return "match: recomputed anomalies identical to the stored event"
	}
	return fmt.Sprintf("REGRESSION: anomalies changed vs stored (added=%v removed=%v)", add, drop)
}

func diffSets(old, new []string) (added, removed []string) {
	o, n := map[string]bool{}, map[string]bool{}
	for _, x := range old {
		o[x] = true
	}
	for _, x := range new {
		n[x] = true
	}
	for x := range n {
		if !o[x] {
			added = append(added, x)
		}
	}
	for x := range o {
		if !n[x] {
			removed = append(removed, x)
		}
	}
	sort.Strings(added)
	sort.Strings(removed)
	return added, removed
}

func clipForReplay(s string) string {
	if len(s) > 512 {
		return s[:512] + "…"
	}
	return s
}

// --- replayConn: a one-shot net.Conn over a byte slice for offline replay ---

type replayConn struct {
	r *bytes.Reader
}

func newReplayConn(b []byte) *replayConn { return &replayConn{r: bytes.NewReader(b)} }

func (c *replayConn) Read(p []byte) (int, error)       { return c.r.Read(p) }
func (c *replayConn) Write(p []byte) (int, error)      { return len(p), nil } // discard responses
func (c *replayConn) Close() error                     { return nil }
func (c *replayConn) LocalAddr() net.Addr              { return fakeAddr{} }
func (c *replayConn) RemoteAddr() net.Addr             { return fakeAddr{} }
func (c *replayConn) SetDeadline(time.Time) error      { return nil }
func (c *replayConn) SetReadDeadline(time.Time) error  { return nil }
func (c *replayConn) SetWriteDeadline(time.Time) error { return nil }

type fakeAddr struct{}

func (fakeAddr) Network() string { return "replay" }
func (fakeAddr) String() string  { return "203.0.113.1:40000" }
