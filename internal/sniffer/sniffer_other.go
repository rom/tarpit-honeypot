//go:build !linux

package sniffer

import (
	"errors"

	"github.com/rom/tarpit-honeypot/internal/config"
)

func newImpl(_ config.Sniffer, _ string) (Sniffer, error) {
	return nil, errors.New("sniffer: AF_PACKET sniffer is Linux-only; Windows support planned for v0.6")
}
