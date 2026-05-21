package handler

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/identity"
	"github.com/rom/tarpit-honeypot/internal/safe"
)

// atg is a Veeder-Root TLS-350 Automatic Tank Gauge responder on TCP 10001
// — the fuel-station console behind the classic "internet-exposed gas
// pump" reports and the nmap atg-info probe. Commands arrive as ^A (0x01)
// followed by a 6-char code (I20100 = in-tank inventory, I20200 = delivery
// report, I20300 = leak test). We answer the common report commands with a
// believable, deterministic tank report and capture the command. Nothing
// is controllable — report-only.
type atg struct{ id *identity.Identity }

func (a *atg) Name() string { return "atg" }

func (a *atg) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	withTimeout(conn, cfg.ReadTimeout)
	res := Result{Meta: map[string]any{}}

	buf := make([]byte, 64)
	n, _ := conn.Read(buf)
	if n <= 0 {
		res.Meta["read_err"] = "no data"
		return res, nil
	}
	req := buf[:n]
	res.Payload = append([]byte(nil), req...)

	cmd := strings.TrimSpace(strings.TrimLeft(string(req), "\x01"))
	if len(cmd) > 16 {
		cmd = cmd[:16]
	}
	res.Meta["atg_command"] = safe.SanitizeForLog(cmd)
	flagAnomaly(&res, "ics-atg-command")

	code := ""
	if len(cmd) >= 6 {
		code = strings.ToUpper(cmd[:6])
	}
	var out string
	switch code {
	case "I20100":
		out = a.report(code, "IN-TANK INVENTORY")
	case "I20200":
		out = a.report(code, "DELIVERY REPORT")
	case "I20300":
		out = a.report(code, "IN-TANK LEAK DETECT")
	default:
		// TLS-350 generic data error.
		out = "\x019999FF1B\x03"
	}
	if _, err := conn.Write([]byte(out)); err != nil {
		res.Meta["write_err"] = err.Error()
	}
	res.BannerSent = "veeder-root tls-350"
	return res, nil
}

// report renders a TLS-350 report: ^A, the echoed command + timestamp, a
// station header, the section title, a per-tank table, then ^C.
func (a *atg) report(code, title string) string {
	station, addr1, addr2 := a.station()
	ts := time.Now().Format("Jan _2, 2006  3:04 PM")
	var b strings.Builder
	b.WriteString("\x01")
	b.WriteString(code)
	b.WriteString(" " + ts + "\r\n\r\n")
	b.WriteString(station + "\r\n")
	b.WriteString(addr1 + "\r\n")
	b.WriteString(addr2 + "\r\n\r\n")
	b.WriteString(title + "\r\n\r\n")
	b.WriteString("TANK PRODUCT             VOLUME TC VOLUME   ULLAGE   HEIGHT    WATER     TEMP\r\n")
	for i, t := range a.tanks() {
		fmt.Fprintf(&b, "%3d  %-18s %6d    %6d   %6d   %6.2f    %5.2f   %6.2f\r\n",
			i+1, t.product, t.volume, t.tcVolume, t.ullage, t.height, t.water, t.temp)
	}
	b.WriteString("\r\n\x03")
	return b.String()
}

type atgTank struct {
	product          string
	volume, tcVolume int
	ullage           int
	height, water    float64
	temp             float64
}

func (a *atg) tanks() []atgTank {
	// Deterministic per-deployment volumes so two sensors differ but each
	// stays self-consistent across queries.
	v := func(label string, base int) int {
		if a.id == nil {
			return base
		}
		return base + int(a.id.Uint32("atg/"+label)%1500)
	}
	mk := func(label, product string, base int, h float64) atgTank {
		vol := v(label, base)
		return atgTank{
			product: product, volume: vol, tcVolume: vol - 90,
			ullage: 10000 - vol, height: h, water: 0.00, temp: 62.40,
		}
	}
	return []atgTank{
		mk("t1", "UNLEADED", 7000, 50.21),
		mk("t2", "PREMIUM", 3200, 28.90),
		mk("t3", "DIESEL", 6100, 45.83),
	}
}

func (a *atg) station() (name, addr1, addr2 string) {
	if a.id == nil {
		return "EXAMPLE FUEL STATION", "123 MAIN ST", "ANYTOWN, USA"
	}
	names := []string{"FILL-N-GO", "QUICK STOP", "GAS EXPRESS", "PETRO MART", "FUEL DEPOT"}
	streets := []string{"100 HIGHWAY 9", "455 COMMERCE DR", "12 INDUSTRIAL PKWY", "880 MARKET ST"}
	cities := []string{"SPRINGFIELD, IL", "RIVERSIDE, CA", "FRANKLIN, TN", "CLINTON, OH"}
	n := names[int(a.id.Uint32("atg/name"))%len(names)]
	num := 100 + int(a.id.Uint32("atg/num")%900)
	return fmt.Sprintf("%s #%d", n, num),
		streets[int(a.id.Uint32("atg/street"))%len(streets)],
		cities[int(a.id.Uint32("atg/city"))%len(cities)]
}
