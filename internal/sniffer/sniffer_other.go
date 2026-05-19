//go:build !linux

package sniffer

import (
	"errors"
	"runtime"

	"github.com/rom/tarpit-honeypot/internal/config"
)

// The AF_PACKET sniffer that detects ARP scans / unsolicited ARP
// replies is Linux-specific. macOS / BSD have /dev/bpf with a
// different API; that backend isn't implemented yet. On other
// platforms the sniffer cleanly refuses to start so the sensor
// continues with all other features enabled.
func newImpl(_ config.Sniffer, _ string) (Sniffer, error) {
	return nil, errors.New("sniffer: AF_PACKET sniffer is linux-only; not available on " + runtime.GOOS +
		" (planned: BPF backend for macOS / BSD)")
}
