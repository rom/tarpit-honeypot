package handler

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
)

// tpktWrap frames body as a TPKT + COTP data (DT) PDU.
func tpktData(body []byte) []byte {
	total := 4 + 3 + len(body)
	out := []byte{0x03, 0x00, byte(total >> 8), byte(total), 0x02, 0xF0, 0x80}
	return append(out, body...)
}

// TestICCPAssociationAndTransferSet drives an ICCP/TASE.2 session: the AARQ
// carries a TASE2 marker, and a Write confirmed-request touches a Transfer
// Set. The handler should label the association ICCP and flag the transfer-set
// manipulation.
func TestICCPAssociationAndTransferSet(t *testing.T) {
	cr := []byte{0x03, 0x00, 0x00, 0x0B, 0x06, 0xE0, 0x00, 0x00, 0x00, 0x01, 0x00}
	// AARQ with a TASE.2 identifier in the user-information.
	aarq := tpktData(append([]byte{0x60, 0x10}, []byte("TASE2_Version")...))
	// Write confirmed-request: 0xA0 cr, invokeID(0x02 0x01 0x01), 0xA5 write,
	// then a TASE.2 Transfer_Set object name.
	wbody := append([]byte{0xA0, 0x16, 0x02, 0x01, 0x01, 0xA5, 0x00}, []byte("DSTransferSet01")...)
	write := tpktData(wbody)
	msg := append(append(append([]byte{}, cr...), aarq...), write...)

	r := driveDrain(t, func(c net.Conn) Result {
		res, _ := (&mms{}).Handle(context.Background(), c, config.Listener{ReadTimeout: time.Second})
		return res
	}, msg)

	if r.Meta["mms_profile"] != "ICCP/TASE.2" {
		t.Errorf("mms_profile = %v; want ICCP/TASE.2", r.Meta["mms_profile"])
	}
	if !hasAnom(r, "ics-iccp-association") {
		t.Errorf("ICCP association not flagged: %v", r.Meta["anomalies"])
	}
	if !hasAnom(r, "ics-iccp-transfer-set") {
		t.Errorf("ICCP transfer-set not flagged: %v", r.Meta["anomalies"])
	}
}

// TestICCPDeviceControl flags a Write touching a Device object on an ICCP link
// as Block-5 cross-utility control.
func TestICCPDeviceControl(t *testing.T) {
	cr := []byte{0x03, 0x00, 0x00, 0x0B, 0x06, 0xE0, 0x00, 0x00, 0x00, 0x01, 0x00}
	aarq := tpktData(append([]byte{0x60, 0x10}, []byte("Bilateral_Table")...))
	wbody := append([]byte{0xA0, 0x14, 0x02, 0x01, 0x01, 0xA5, 0x00}, []byte("Device_Breaker_Tag")...)
	write := tpktData(wbody)
	msg := append(append(append([]byte{}, cr...), aarq...), write...)

	r := driveDrain(t, func(c net.Conn) Result {
		res, _ := (&mms{}).Handle(context.Background(), c, config.Listener{ReadTimeout: time.Second})
		return res
	}, msg)
	if !hasAnom(r, "ics-iccp-control") {
		t.Errorf("ICCP device control not flagged: %v", r.Meta["anomalies"])
	}
}

// A plain substation MMS session (no TASE.2 markers) must NOT be labelled ICCP.
func TestMMSNotMislabeledICCP(t *testing.T) {
	cr := []byte{0x03, 0x00, 0x00, 0x0B, 0x06, 0xE0, 0x00, 0x00, 0x00, 0x01, 0x00}
	aarq := tpktData([]byte{0x60, 0x04, 0x02, 0x01, 0x01})
	read := tpktData([]byte{0xA0, 0x06, 0x02, 0x01, 0x01, 0xA4, 0x00})
	msg := append(append(append([]byte{}, cr...), aarq...), read...)
	r := driveDrain(t, func(c net.Conn) Result {
		res, _ := (&mms{}).Handle(context.Background(), c, config.Listener{ReadTimeout: time.Second})
		return res
	}, msg)
	if r.Meta["mms_profile"] != nil {
		t.Errorf("non-ICCP MMS mislabelled: %v", r.Meta["mms_profile"])
	}
	if hasAnom(r, "ics-iccp-association") {
		t.Error("non-ICCP MMS flagged as ICCP")
	}
}
