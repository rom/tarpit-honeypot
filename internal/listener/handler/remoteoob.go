package handler

import (
	"context"
	"encoding/binary"
	"net"
	"strings"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/safe"
)

// Round-five remote-access / out-of-band-management decoys. The legacy
// Berkeley r-services (rexec/rsh) capture the credentials and command an
// attacker sends in the clear; the third-party remote-control and VDI
// protocols (radmin/dameware/pcAnywhere/PCoIP/SPICE/ARD) and the serial /
// mainframe access surfaces (Lantronix/TN3270) answer just enough to look
// real to a scanner and flag the probe. Each reads a bounded request.

// --- rexec (512) ---------------------------------------------------------
//
// The Berkeley remote-exec service runs a command after a cleartext
// user/password — so the request itself carries credentials. Format:
// "stderr_port\0username\0password\0command\0". We capture all three and
// answer a rejection.
type rexec struct{}

func (h *rexec) Name() string { return "rexec" }

func (h *rexec) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	res := Result{Meta: map[string]any{}}
	got := readCapped(conn, cfg, make([]byte, 2048))
	res.Payload = got
	flagAnomaly(&res, "rexec-attempt")
	fields := strings.Split(string(got), "\x00")
	// [0]=stderr port, [1]=user, [2]=password, [3]=command.
	var user, pass string
	if len(fields) >= 2 {
		user = fields[1]
		res.Meta["username"] = safe.SanitizeForLog(user)
	}
	if len(fields) >= 3 {
		pass = fields[2]
		res.Meta["password"] = safe.SanitizeForLog(pass)
	}
	if len(fields) >= 4 && fields[3] != "" {
		res.Meta["command"] = safe.SanitizeForLog(fields[3])
		flagAnomaly(&res, "rexec-command")
	}
	flagDefaultCred(&res, user, pass)
	_, _ = conn.Write([]byte{0x01}) // non-zero = rejected
	_, _ = conn.Write([]byte("Permission denied.\n"))
	res.BannerSent = "rexec rejected"
	return res, nil
}

// --- rsh (514) -----------------------------------------------------------
//
// The Berkeley remote-shell service runs a command under .rhosts trust (no
// password). Format: "stderr_port\0local_user\0remote_user\0command\0". We
// capture the users + command and reject.
type rsh struct{}

func (h *rsh) Name() string { return "rsh" }

func (h *rsh) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	res := Result{Meta: map[string]any{}}
	got := readCapped(conn, cfg, make([]byte, 2048))
	res.Payload = got
	flagAnomaly(&res, "rsh-attempt")
	fields := strings.Split(string(got), "\x00")
	if len(fields) >= 2 {
		res.Meta["local_user"] = safe.SanitizeForLog(fields[1])
	}
	if len(fields) >= 3 {
		res.Meta["remote_user"] = safe.SanitizeForLog(fields[2])
	}
	if len(fields) >= 4 && fields[3] != "" {
		res.Meta["command"] = safe.SanitizeForLog(fields[3])
		flagAnomaly(&res, "rsh-command")
	}
	_, _ = conn.Write([]byte{0x01})
	_, _ = conn.Write([]byte("Permission denied.\n"))
	res.BannerSent = "rsh rejected"
	return res, nil
}

// --- Symantec pcAnywhere (5631) ------------------------------------------
//
// pcAnywhere is a long-scanned Windows remote-control service. The host
// answers a status/identification banner; we send the recognizable
// pcAnywhere greeting and flag the probe.
type pcanywhere struct{}

func (h *pcanywhere) Name() string { return "pcanywhere" }

func (h *pcanywhere) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	res := Result{Meta: map[string]any{}}
	// pcAnywhere host speaks first with a short control sequence.
	_, _ = conn.Write([]byte{0x00, 0x00, 0x00, 0x00, 0x1b, 0x00})
	got := readCapped(conn, cfg, make([]byte, 512))
	res.Payload = got
	flagAnomaly(&res, "pcanywhere-probe")
	res.BannerSent = "pcanywhere status"
	return res, nil
}

// --- Famatech Radmin (4899) ----------------------------------------------
//
// Radmin is a proprietary Windows remote-admin protocol; a fingerprint-grade
// responder is enough for a scanner to record a live Radmin host. We read the
// client's opening message and answer a short canned reply.
type radmin struct{}

func (h *radmin) Name() string { return "radmin" }

func (h *radmin) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	res := Result{Meta: map[string]any{}}
	got := readCapped(conn, cfg, make([]byte, 512))
	res.Payload = got
	flagAnomaly(&res, "radmin-probe")
	_, _ = conn.Write([]byte{0x01, 0x00, 0x00, 0x00, 0x25}) // server hello-ish
	res.BannerSent = "radmin reply"
	return res, nil
}

// --- SolarWinds DameWare Mini Remote Control (6129) ----------------------
//
// DameWare MRC is a Windows remote-control service. We answer with a short
// canned banner so a scanner records a live MRC host and flag the probe.
type dameware struct{}

func (h *dameware) Name() string { return "dameware" }

func (h *dameware) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	res := Result{Meta: map[string]any{}}
	_, _ = conn.Write([]byte{0x30, 0x11, 0x00, 0x00}) // MRC server greeting prefix
	got := readCapped(conn, cfg, make([]byte, 512))
	res.Payload = got
	flagAnomaly(&res, "dameware-probe")
	res.BannerSent = "dameware greeting"
	return res, nil
}

// --- Teradici PCoIP (4172) -----------------------------------------------
//
// PCoIP is the VDI remote-display protocol (VMware Horizon / Teradici). We
// flag the probe and answer minimally so a scanner records a live broker/host.
type pcoip struct{}

func (h *pcoip) Name() string { return "pcoip" }

func (h *pcoip) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	res := Result{Meta: map[string]any{}}
	got := readCapped(conn, cfg, make([]byte, 512))
	res.Payload = got
	flagAnomaly(&res, "pcoip-probe")
	_, _ = conn.Write([]byte{0x00, 0x00, 0x00, 0x01})
	res.BannerSent = "pcoip reply"
	return res, nil
}

// --- SPICE (5930) --------------------------------------------------------
//
// SPICE is the remote-display protocol for QEMU/KVM virtual-machine consoles.
// The client opens with a SpiceLinkMess whose magic is "REDQ"; we verify it
// and answer a SpiceLinkReply so a scanner records a live VM console.
type spice struct{}

func (h *spice) Name() string { return "spice" }

func (h *spice) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	res := Result{Meta: map[string]any{}}
	got := readCapped(conn, cfg, make([]byte, 512))
	res.Payload = got
	flagAnomaly(&res, "spice-probe")
	if len(got) < 4 || string(got[0:4]) != "REDQ" {
		return res, nil
	}
	// SpiceLinkReply: magic "REDQ", major(2), minor(2), size(4), error(4)=0.
	reply := append([]byte{}, "REDQ"...)
	reply = binary.LittleEndian.AppendUint32(reply, 2) // major version
	reply = binary.LittleEndian.AppendUint32(reply, 2) // minor version
	reply = binary.LittleEndian.AppendUint32(reply, 0) // payload size
	reply = binary.LittleEndian.AppendUint32(reply, 0) // SPICE_LINK_ERR_OK
	_, _ = conn.Write(reply)
	res.BannerSent = "spice link reply"
	return res, nil
}

// --- Lantronix serial device server setup (9999) -------------------------
//
// Lantronix serial-to-Ethernet device servers expose a setup port that leaks
// the MAC, firmware and a config menu — the entry point to whatever serial OT
// gear hangs off them. We greet with the recognizable setup banner and flag
// the probe.
type lantronix struct{}

func (h *lantronix) Name() string { return "lantronix" }

func (h *lantronix) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	res := Result{Meta: map[string]any{}}
	_, _ = conn.Write([]byte("\r\n*** Lantronix Device Server ***\r\n" +
		"MAC address 00204A1B2C3D\r\nSoftware version V6.8.0.1 (140218)\r\n\r\n" +
		"Press Enter for Setup Mode\r\n"))
	got := readCapped(conn, cfg, make([]byte, 512))
	res.Payload = got
	flagAnomaly(&res, "lantronix-probe")
	res.BannerSent = "lantronix setup"
	return res, nil
}

// --- TN3270 (23 / 992) ---------------------------------------------------
//
// TN3270 is the IBM mainframe terminal protocol — a live one means a z/OS
// system behind it. We answer the opening Telnet negotiation and present a
// mainframe logon banner so a scanner records a mainframe, and flag the probe.
type tn3270 struct{}

func (h *tn3270) Name() string { return "tn3270" }

func (h *tn3270) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	res := Result{Meta: map[string]any{}}
	// IAC WILL SGA, IAC WILL ECHO, IAC DO TN3270E.
	_, _ = conn.Write([]byte{0xff, 0xfb, 0x03, 0xff, 0xfb, 0x01, 0xff, 0xfd, 0x28})
	got := readCapped(conn, cfg, make([]byte, 512))
	res.Payload = got
	flagAnomaly(&res, "tn3270-probe")
	_, _ = conn.Write([]byte("\r\n  z/OS TSO/E LOGON\r\n\r\n  Enter LOGON parameters\r\n  Userid    ===> "))
	res.BannerSent = "tn3270 logon"
	return res, nil
}

// --- Apple Remote Desktop (3283) -----------------------------------------
//
// ARD's net-assistant service is the macOS remote-management surface. We flag
// the probe and answer minimally so a scanner records a live ARD agent.
type ard struct{}

func (h *ard) Name() string { return "ard" }

func (h *ard) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	res := Result{Meta: map[string]any{}}
	got := readCapped(conn, cfg, make([]byte, 512))
	res.Payload = got
	flagAnomaly(&res, "ard-probe")
	_, _ = conn.Write([]byte{0x00, 0x01, 0x00, 0x00})
	res.BannerSent = "ard reply"
	return res, nil
}
