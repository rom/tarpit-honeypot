package handler

import (
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"
)

func TestNBDListEnumeration(t *testing.T) {
	client, server := loopbackPair(t)
	var b []byte
	b = append(b, 0, 0, 0, 1)               // client flags
	b = append(b, []byte("IHAVEOPT")...)    // option magic
	b = binary.BigEndian.AppendUint32(b, 3) // NBD_OPT_LIST
	b = binary.BigEndian.AppendUint32(b, 0) // data length 0
	if _, err := client.Write(b); err != nil {
		t.Fatal(err)
	}
	res, err := (&nbd{}).Handle(context.Background(), server, smallSvcCfg())
	if err != nil {
		t.Fatal(err)
	}
	if res.Meta["nbd_option"] != "LIST" {
		t.Errorf("nbd_option = %v; want LIST", res.Meta["nbd_option"])
	}
	if !hasAnomaly(res, "nbd-export-enumeration") || !hasAnomaly(res, "nbd-handshake") {
		t.Errorf("nbd flags missing: %v", res.Meta["anomalies"])
	}
	// The greeting on the wire must be the NBD newstyle magic.
	buf := make([]byte, 18)
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	if n, _ := client.Read(buf); n < 16 || string(buf[:8]) != "NBDMAGIC" {
		t.Errorf("greeting = %q", string(buf[:n]))
	}
}

func TestNBDExportName(t *testing.T) {
	client, server := loopbackPair(t)
	name := []byte("prod-disk")
	var b []byte
	b = append(b, 0, 0, 0, 1)
	b = append(b, []byte("IHAVEOPT")...)
	b = binary.BigEndian.AppendUint32(b, 1) // EXPORT_NAME
	b = binary.BigEndian.AppendUint32(b, uint32(len(name)))
	b = append(b, name...)
	if _, err := client.Write(b); err != nil {
		t.Fatal(err)
	}
	res, _ := (&nbd{}).Handle(context.Background(), server, smallSvcCfg())
	if res.Meta["nbd_export"] != "prod-disk" {
		t.Errorf("nbd_export = %v; want prod-disk", res.Meta["nbd_export"])
	}
}

func TestStatsdCapture(t *testing.T) {
	res, err := (&statsd{}).Handle(context.Background(), []byte("api.cpu:1|c\napi.mem:50|g\n"), &net.UDPAddr{}, nil, smallSvcCfg())
	if err != nil {
		t.Fatal(err)
	}
	if res.Meta["statsd_metrics"] != 2 {
		t.Errorf("statsd_metrics = %v; want 2", res.Meta["statsd_metrics"])
	}
	if !hasAnomaly(res, "statsd-metric-received") {
		t.Errorf("statsd flag missing: %v", res.Meta["anomalies"])
	}
}
