package handler

import (
	"context"
	"net"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/identity"
	"github.com/rom/tarpit-honeypot/internal/safe"
)

// foxH is a Niagara / Tridium Fox responder on TCP 1911 (and 4911 for
// foxs/TLS) — the building-automation framework Shodan fingerprints with
// its "fox" probe. On connect a real station sends a "fox hello" frame
// advertising its station name, host id, app/VM/OS versions, and brand.
// We emit a believable, per-deployment hello and capture the client's
// follow-up. This is the single most-scanned BAS banner; exposing it draws
// targeted BAS recon. No control surface.
type foxH struct{ id *identity.Identity }

func (f *foxH) Name() string { return "fox" }

func (f *foxH) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	withTimeout(conn, cfg.ReadTimeout)
	res := Result{Meta: map[string]any{}}

	banner := f.hello()
	if _, err := conn.Write([]byte(banner)); err != nil {
		res.Meta["write_err"] = err.Error()
		return res, nil
	}
	res.BannerSent = banner

	buf := make([]byte, 2048)
	n, _ := conn.Read(buf)
	if n > 0 {
		res.Payload = append([]byte(nil), buf[:n]...)
		snip := buf[:n]
		if len(snip) > 256 {
			snip = snip[:256]
		}
		res.Meta["fox_request"] = safe.SanitizeForLog(string(snip))
	}
	flagAnomaly(&res, "ics-fox-probe")
	return res, nil
}

// hello builds a Fox hello frame. The framing is "fox a 0 -1 fox hello\n{
// key=type:value ... };;\n". Field values are deployment-derived so two
// sensors present distinct stations.
func (f *foxH) hello() string {
	host, station, hostID, vmUUID := "controller", "Station", "Qnx-NPM6-0000-1A2B-3C4D", "b8e1a2c3-0000-1111-2222-333344445555"
	if f.id != nil {
		hex6 := safeHex(f.id.Bytes("fox/hostid", 6))
		host = "npm-" + safeHex(f.id.Bytes("fox/host", 2))
		stations := []string{"JACE_8000", "MainPlant", "AHU_North", "BuildingA", "CentralPlant"}
		station = stations[int(f.id.Uint32("fox/station"))%len(stations)]
		hostID = "Qnx-NPM6-" + hex6[:4] + "-" + hex6[4:8] + "-" + hex6[8:12]
		vmUUID = safeHex(f.id.Bytes("fox/uuid", 16))
	}
	return "fox a 0 -1 fox hello\n{\n" +
		"fox.version=s:1.0.1\n" +
		"id=i:1\n" +
		"hostName=s:" + host + "\n" +
		"hostAddress=s:0.0.0.0\n" +
		"app.name=s:Workbench\n" +
		"app.version=s:3.8.38\n" +
		"vm.name=s:Java HotSpot(TM) Server VM\n" +
		"vm.version=s:1.8.0_112\n" +
		"os.name=s:QNX\n" +
		"os.version=s:6.5.0\n" +
		"station.name=s:" + station + "\n" +
		"lang=s:en\n" +
		"timeZone=s:America/New_York;-18000000;3600000;...\n" +
		"hostId=s:" + hostID + "\n" +
		"vmUuid=s:" + vmUUID + "\n" +
		"brandId=s:vykon\n" +
		"};;\n"
}

func safeHex(b []byte) string {
	const hexd = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, x := range b {
		out = append(out, hexd[x>>4], hexd[x&0x0f])
	}
	s := string(out)
	for len(s) < 16 {
		s += "0"
	}
	return s
}
