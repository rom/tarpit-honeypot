//go:build !linux

package tunnet

import (
	"context"
	"errors"
)

type Config struct {
	DeviceName string
	CIDRs      []string
	HostIPs    []string
	MTU        int
}

type Adapter struct{}

func New(_ Config) (*Adapter, error) {
	return nil, errors.New("tunnet: linux-only")
}

func (a *Adapter) Run(_ context.Context) error { return errors.New("tunnet: linux-only") }
func (a *Adapter) Close() error                { return nil }
