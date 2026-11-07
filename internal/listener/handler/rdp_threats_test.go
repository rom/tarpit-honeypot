package handler

import (
	"context"
	"encoding/binary"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
)

// rdpConnReq builds a TPKT + X.224 Connection Request carrying an optional
// mstshash cookie and an RDP_NEG_REQ requesting the given protocol bitmask.
func rdpConnReq(cookie string, proto uint32) []byte {
	var variable []byte
	if cookie != "" {
		variable = append(variable, []byte("Cookie: mstshash="+cookie+"\r\n")...)
	}
	neg := []byte{0x01, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00} // type, flags, len, proto
	binary.LittleEndian.PutUint32(neg[4:8], proto)
	variable = append(variable, neg...)

	// X.224 CR: len, 0xE0, dst(2), src(2), class(1), variable
	x224 := []byte{byte(6 + len(variable)), 0xE0, 0x00, 0x00, 0x00, 0x00, 0x00}
	x224 = append(x224, variable...)
	tpkt := []byte{0x03, 0x00, byte((4 + len(x224)) >> 8), byte((4 + len(x224)) & 0xff)}
	return append(tpkt, x224...)
}

func TestRDPHarvestAndDowngrade(t *testing.T) {
	drive := func(req []byte) Result {
		client, server := pipePair(t)
		done := make(chan struct{})
		var res Result
		go func() {
			defer close(done)
			res, _ = newRDP(Deps{}).Handle(context.Background(), server, config.Listener{ReadTimeout: time.Second})
		}()
		_, _ = client.Write(req)
		buf := make([]byte, 64)
		_ = client.SetReadDeadline(time.Now().Add(time.Second))
		_, _ = client.Read(buf)
		_ = client.Close()
		<-done
		return res
	}

	// mstshash cookie + standard-RDP (proto 0) => harvest + NLA downgrade.
	res := drive(rdpConnReq("administrator", 0))
	if c, _ := res.Meta["cookie"].(string); c == "" || !hasAnom(res, "rdp-username-harvest") {
		t.Errorf("mstshash harvest not flagged: %v", res.Meta)
	}
	// The mstshash= prefix must be stripped so the bare username flows into
	// the credential store / export-creds.
	if u, _ := res.Meta["username"].(string); u != "administrator" {
		t.Errorf("mstshash username = %q; want administrator (meta=%v)", u, res.Meta)
	}
	if !hasAnom(res, "rdp-nla-downgrade") {
		t.Errorf("NLA downgrade (proto 0) not flagged: %v", res.Meta["anomalies"])
	}

	// HYBRID requested (proto 3) => no downgrade marker.
	res2 := drive(rdpConnReq("", 0x03))
	if hasAnom(res2, "rdp-nla-downgrade") {
		t.Errorf("HYBRID request wrongly flagged as downgrade: %v", res2.Meta["anomalies"])
	}
}
