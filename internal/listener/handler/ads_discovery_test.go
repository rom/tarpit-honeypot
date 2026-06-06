package handler

import (
	"encoding/binary"
	"testing"
)

func amsUDP(service uint32, tail []byte) []byte {
	b := make([]byte, 16)
	binary.LittleEndian.PutUint32(b[0:4], amsUDPMagic)
	binary.LittleEndian.PutUint32(b[4:8], service)
	copy(b[8:14], []byte{192, 168, 0, 50, 1, 1}) // sender AmsNetId
	binary.LittleEndian.PutUint16(b[14:16], 10000)
	return append(b, tail...)
}

func TestADSDiscoveryIdentify(t *testing.T) {
	res := udpResult(t, &adsDiscovery{lim: newUDPReflectLimiter()}, amsUDP(1, nil))
	if !hasAnom(res, "ics-ads-discovery") {
		t.Errorf("discovery not flagged: %v", res.Meta["anomalies"])
	}
	if res.Meta["ams_udp_service"] != "Identify/Discovery" {
		t.Errorf("service = %v", res.Meta["ams_udp_service"])
	}
	if res.Meta["ams_source"] != "192.168.0.50.1.1" {
		t.Errorf("ams_source = %v", res.Meta["ams_source"])
	}
}

func TestADSDiscoveryAddRoute(t *testing.T) {
	// AddRoute carries route/host/user strings in its tail.
	tail := []byte("Route1\x00DESKTOP-EVIL\x00Administrator\x00")
	res := udpResult(t, &adsDiscovery{lim: newUDPReflectLimiter()}, amsUDP(6, tail))
	if !hasAnom(res, "ics-ads-route-add") {
		t.Errorf("AddRoute not flagged: %v", res.Meta["anomalies"])
	}
	fields, _ := res.Meta["ams_route_fields"].([]string)
	if !containsStr(fields, "Administrator") {
		t.Errorf("route fields did not capture the username: %v", fields)
	}
}
