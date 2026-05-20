package handler

import (
	"bufio"
	"context"
	"net"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
)

// The classic inetd "small services" (RFC 862-868, 1340 QOTD). They
// are trivial but commonly probed — and chargen/echo are DDoS-reflector
// favorites, so a honeypot that exposes them must NOT actually amplify.
// Our chargen/echo replies are strictly bounded (one capped response,
// never the unbounded stream a real chargen sends) so we capture the
// probe without becoming a reflector.
//
// TCP variants implement the Handler interface; UDP variants implement
// UDPHandler. Both capture what the client sent and reply with the
// canned small-service payload.

// ---- shared payloads ----

// daytimeString is the RFC 867 human-readable timestamp.
func daytimeString() string {
	return time.Now().UTC().Format("Mon Jan  2 15:04:05 2006") + "\r\n"
}

// rfc868Time returns the RFC 868 32-bit seconds-since-1900 timestamp.
func rfc868Time() []byte {
	// seconds between 1900-01-01 and 1970-01-01 = 2208988800.
	secs := uint32(time.Now().Unix() + 2208988800)
	return []byte{byte(secs >> 24), byte(secs >> 16), byte(secs >> 8), byte(secs)}
}

const qotdText = "\"The only system which is truly secure is one which is switched " +
	"off and unplugged.\" - Gene Spafford\r\n"

// chargenLine is one capped line of the RFC 864 character-generator
// pattern (the rotating ASCII 0x20-0x7E ruler). A real chargen streams
// forever; we send exactly one 72-char line + CRLF and stop, so we
// can't be used as a reflector/amplifier.
func chargenLine() []byte {
	const printable = 95 // 0x20..0x7E
	out := make([]byte, 0, 74)
	for i := 0; i < 72; i++ {
		out = append(out, byte(0x20+(i%printable)))
	}
	out = append(out, '\r', '\n')
	return out
}

// ---- TCP ----

// echoTCP (port 7) reads a bounded amount and echoes it back once.
type echoTCP struct{}

func (e *echoTCP) Name() string { return "echo" }
func (e *echoTCP) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	withTimeout(conn, cfg.ReadTimeout)
	res := Result{Meta: map[string]any{}}
	cap := cfg.ReadBytes
	if cap <= 0 || cap > 4096 {
		cap = 1024
	}
	br := bufio.NewReader(conn)
	buf := make([]byte, cap)
	n, _ := br.Read(buf)
	if n > 0 {
		res.Payload = append([]byte(nil), buf[:n]...)
		res.Meta["echoed_bytes"] = n
		_, _ = conn.Write(buf[:n]) // single bounded echo — no loop, no amplification
	}
	res.BannerSent = "echo"
	return res, nil
}

// discardTCP (port 9) reads + drops; never replies.
type discardTCP struct{}

func (d *discardTCP) Name() string { return "discard" }
func (d *discardTCP) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	withTimeout(conn, cfg.ReadTimeout)
	res := Result{Meta: map[string]any{}}
	cap := cfg.ReadBytes
	if cap <= 0 || cap > 4096 {
		cap = 1024
	}
	buf := make([]byte, cap)
	n, _ := conn.Read(buf)
	if n > 0 {
		res.Payload = append([]byte(nil), buf[:n]...)
		res.Meta["discarded_bytes"] = n
	}
	res.BannerSent = ""
	return res, nil
}

// daytimeTCP (port 13) sends the human-readable time and closes.
type daytimeTCP struct{}

func (d *daytimeTCP) Name() string { return "daytime" }
func (d *daytimeTCP) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	withTimeout(conn, cfg.ReadTimeout)
	s := daytimeString()
	_, _ = conn.Write([]byte(s))
	return Result{BannerSent: s}, nil
}

// qotdTCP (port 17) sends a quote and closes.
type qotdTCP struct{}

func (q *qotdTCP) Name() string { return "qotd" }
func (q *qotdTCP) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	withTimeout(conn, cfg.ReadTimeout)
	_, _ = conn.Write([]byte(qotdText))
	return Result{BannerSent: qotdText}, nil
}

// chargenTCP (port 19) sends ONE bounded line, captures any input.
type chargenTCP struct{}

func (c *chargenTCP) Name() string { return "chargen" }
func (c *chargenTCP) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	withTimeout(conn, cfg.ReadTimeout)
	res := Result{Meta: map[string]any{}}
	line := chargenLine()
	_, _ = conn.Write(line)
	res.BannerSent = "chargen (1 line, bounded)"
	return res, nil
}

// timeTCP (port 37) sends the 4-byte RFC 868 time and closes.
type timeTCP struct{}

func (t *timeTCP) Name() string { return "time" }
func (t *timeTCP) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	withTimeout(conn, cfg.ReadTimeout)
	b := rfc868Time()
	_, _ = conn.Write(b)
	return Result{BannerSent: "rfc868-time", Payload: b}, nil
}

// ---- UDP ----
//
// The UDP small services are the reflection-amplifier targets, so each
// replies with at most ONE bounded datagram and never echoes more than
// it received (echo) — refusing to amplify.

type echoUDP struct{}

func (e *echoUDP) Name() string { return "echo" }
func (e *echoUDP) Handle(_ context.Context, payload []byte, src net.Addr, pc net.PacketConn, _ config.Listener) (Result, error) {
	res := Result{Payload: append([]byte(nil), payload...), Meta: map[string]any{"echoed_bytes": len(payload)}}
	// Echo back at most what we received (1:1, never amplifying).
	out := payload
	if len(out) > 1024 {
		out = out[:1024]
	}
	_, _ = pc.WriteTo(out, src)
	res.BannerSent = "echo"
	return res, nil
}

type discardUDP struct{}

func (d *discardUDP) Name() string { return "discard" }
func (d *discardUDP) Handle(_ context.Context, payload []byte, _ net.Addr, _ net.PacketConn, _ config.Listener) (Result, error) {
	return Result{Payload: append([]byte(nil), payload...), Meta: map[string]any{"discarded_bytes": len(payload)}}, nil
}

type daytimeUDP struct{}

func (d *daytimeUDP) Name() string { return "daytime" }
func (d *daytimeUDP) Handle(_ context.Context, payload []byte, src net.Addr, pc net.PacketConn, _ config.Listener) (Result, error) {
	s := daytimeString()
	_, _ = pc.WriteTo([]byte(s), src)
	return Result{Payload: append([]byte(nil), payload...), BannerSent: s}, nil
}

type qotdUDP struct{}

func (q *qotdUDP) Name() string { return "qotd" }
func (q *qotdUDP) Handle(_ context.Context, payload []byte, src net.Addr, pc net.PacketConn, _ config.Listener) (Result, error) {
	_, _ = pc.WriteTo([]byte(qotdText), src)
	return Result{Payload: append([]byte(nil), payload...), BannerSent: qotdText}, nil
}

type chargenUDP struct{}

func (c *chargenUDP) Name() string { return "chargen" }
func (c *chargenUDP) Handle(_ context.Context, payload []byte, src net.Addr, pc net.PacketConn, _ config.Listener) (Result, error) {
	// A real UDP chargen replies with a random-length burst — the
	// amplifier behavior. We send exactly one bounded line, so a
	// spoofed-source probe gets a 74-byte reply, never an amplified
	// flood. The probe is still captured.
	res := Result{Payload: append([]byte(nil), payload...), Meta: map[string]any{}}
	_, _ = pc.WriteTo(chargenLine(), src)
	res.BannerSent = "chargen (1 line, bounded)"
	flagAnomaly(&res, "udp-amplifier-probe") // chargen is an amp target; the probe itself is notable
	return res, nil
}

type timeUDP struct{}

func (t *timeUDP) Name() string { return "time" }
func (t *timeUDP) Handle(_ context.Context, payload []byte, src net.Addr, pc net.PacketConn, _ config.Listener) (Result, error) {
	b := rfc868Time()
	_, _ = pc.WriteTo(b, src)
	return Result{Payload: append([]byte(nil), payload...), BannerSent: "rfc868-time"}, nil
}
