package filter

import (
	"net/netip"
)

type Allowlist struct {
	prefixes []netip.Prefix
	addrs    []netip.Addr
}

func NewAllowlist(items []string) (*Allowlist, error) {
	a := &Allowlist{}
	for _, s := range items {
		if p, err := netip.ParsePrefix(s); err == nil {
			a.prefixes = append(a.prefixes, p)
			continue
		}
		addr, err := netip.ParseAddr(s)
		if err != nil {
			return nil, err
		}
		a.addrs = append(a.addrs, addr)
	}
	return a, nil
}

func (a *Allowlist) Contains(ip string) bool {
	if a == nil {
		return false
	}
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	for _, p := range a.prefixes {
		if p.Contains(addr) {
			return true
		}
	}
	for _, x := range a.addrs {
		if x == addr {
			return true
		}
	}
	return false
}
