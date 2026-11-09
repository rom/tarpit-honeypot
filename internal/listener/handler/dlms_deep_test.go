package handler

import (
	"bufio"
	"encoding/binary"
	"io"
	"strings"
	"testing"
	"time"
)

// dlmsWrap frames an xDLMS APDU in the DLMS/COSEM TCP wrapper (version 0x0001,
// src wPort 0x0010, dst wPort 0x0001, length).
func dlmsWrap(apdu []byte) []byte {
	h := []byte{0x00, 0x01, 0x00, 0x10, 0x00, 0x01, 0x00, byte(len(apdu))}
	return append(h, apdu...)
}

// readDLMSReply drains one wrapped reply so the net.Pipe write on the handler
// side doesn't block the next request.
func readDLMSReply(t *testing.T, br *bufio.Reader) {
	t.Helper()
	h := make([]byte, 8)
	if _, err := io.ReadFull(br, h); err != nil {
		t.Fatalf("read dlms reply header: %v", err)
	}
	if n := int(binary.BigEndian.Uint16(h[6:8])); n > 0 {
		if _, err := io.ReadFull(br, make([]byte, n)); err != nil {
			t.Fatalf("read dlms reply body: %v", err)
		}
	}
}

// TestDLMSGetRequestDecoded: after the association, a GET-Request is decoded down
// to the targeted COSEM object (class id + OBIS code + attribute), and the
// primary dlms_apdu reflects the data command, not just the association.
func TestDLMSGetRequestDecoded(t *testing.T) {
	cli, resCh := runHandler(dlmsH{})
	_ = cli.SetDeadline(time.Now().Add(2 * time.Second))
	br := bufio.NewReader(cli)

	if _, err := cli.Write(dlmsWrap([]byte{0x60, 0x02, 0x80, 0x00})); err != nil { // AARQ
		t.Fatal(err)
	}
	readDLMSReply(t, br) // AARE

	// GET-Request-Normal: invoke 0x81, Register (class 3), OBIS 1-0:1.8.0.255, attr 2.
	get := []byte{0xC0, 0x01, 0x81, 0x00, 0x03, 0x01, 0x00, 0x01, 0x08, 0x00, 0xFF, 0x02}
	if _, err := cli.Write(dlmsWrap(get)); err != nil {
		t.Fatal(err)
	}
	readDLMSReply(t, br) // GET-Response
	_ = cli.Close()

	res := <-resCh
	if apdu, _ := res.Meta["dlms_apdu"].(string); !strings.HasPrefix(apdu, "GET-Request") {
		t.Errorf("dlms_apdu = %q; want GET-Request…", apdu)
	}
	if res.Meta["dlms_obis"] != "1-0:1.8.0.255" {
		t.Errorf("dlms_obis = %v; want 1-0:1.8.0.255", res.Meta["dlms_obis"])
	}
	if res.Meta["dlms_attribute"] != 2 {
		t.Errorf("dlms_attribute = %v; want 2", res.Meta["dlms_attribute"])
	}
	if !metaHasAnomaly(res.Meta, "ics-dlms-command") {
		t.Errorf("ics-dlms-command not flagged: %v", res.Meta["anomalies"])
	}
}

// TestDLMSActionRequestDecoded: an ACTION-Request (e.g. a remote-disconnect
// method on the disconnect-control object) is decoded as a control action.
func TestDLMSActionRequestDecoded(t *testing.T) {
	cli, resCh := runHandler(dlmsH{})
	_ = cli.SetDeadline(time.Now().Add(2 * time.Second))
	br := bufio.NewReader(cli)

	if _, err := cli.Write(dlmsWrap([]byte{0x60, 0x02, 0x80, 0x00})); err != nil { // AARQ
		t.Fatal(err)
	}
	readDLMSReply(t, br)

	// ACTION-Request-Normal: Disconnect Control (class 70), OBIS 0-0:96.3.10.255, method 1 (remote_disconnect).
	act := []byte{0xC3, 0x01, 0x82, 0x00, 0x46, 0x00, 0x00, 0x60, 0x03, 0x0A, 0xFF, 0x01}
	if _, err := cli.Write(dlmsWrap(act)); err != nil {
		t.Fatal(err)
	}
	readDLMSReply(t, br)
	_ = cli.Close()

	res := <-resCh
	if apdu, _ := res.Meta["dlms_apdu"].(string); !strings.HasPrefix(apdu, "ACTION-Request") {
		t.Errorf("dlms_apdu = %q; want ACTION-Request…", apdu)
	}
	if res.Meta["dlms_method"] != 1 {
		t.Errorf("dlms_method = %v; want 1", res.Meta["dlms_method"])
	}
	if !metaHasAnomaly(res.Meta, "ics-plc-mode-change") {
		t.Errorf("ACTION not flagged as a control action: %v", res.Meta["anomalies"])
	}
}
