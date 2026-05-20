package handler

import (
	"context"
	"net"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/jitter"
	"github.com/rom/tarpit-honeypot/internal/luaengine"
)

// luaH runs an operator-supplied Lua script as the connection responder.
// The script is compiled once (at construction) and executed per
// connection inside the sandboxed engine, which enforces read/write/sleep
// budgets and a context deadline so a script can't exhaust the sensor or
// amplify.
type luaH struct {
	eng *luaengine.Engine
	jit *jitter.Jitterer
}

func (h *luaH) Name() string { return "lua" }

func (h *luaH) Handle(ctx context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	to := cfg.ReadTimeout
	if to <= 0 {
		to = 60 * time.Second
	}
	withTimeout(conn, to)
	h.jit.Sleep(ctx)

	// Bound the script's total wall-clock time with a context deadline so
	// an infinite loop is cancelled (gopher-lua honors ctx).
	rctx, cancel := context.WithTimeout(ctx, to)
	defer cancel()

	r := h.eng.Run(rctx, conn, hostFromAddr(conn.RemoteAddr()))
	res := Result{BannerSent: r.BannerSent, Payload: r.Payload, Meta: r.Meta}
	for _, a := range r.Anomalies {
		flagAnomaly(&res, a)
	}
	return res, nil
}

// hostFromAddr returns the IP portion of a net.Addr, or its string form.
func hostFromAddr(a net.Addr) string {
	if a == nil {
		return ""
	}
	if h, _, err := net.SplitHostPort(a.String()); err == nil {
		return h
	}
	return a.String()
}
