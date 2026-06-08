package sensor

import (
	"reflect"
	"sort"
	"testing"

	"github.com/rom/tarpit-honeypot/internal/config"
)

func TestResolveBinds(t *testing.T) {
	mk := func(listen []string) *Sensor {
		c := &config.Config{}
		c.Sensor.ListenAddresses = listen
		return &Sensor{name: "t", cfg: c}
	}
	cases := []struct {
		name   string
		listen []string
		bind   string
		want   []string
	}{
		{name: "wildcard no addresses stays wildcard", bind: "[::]:22", want: []string{"[::]:22"}},
		{name: "ipv4 wildcard stays", bind: "0.0.0.0:80", want: []string{"0.0.0.0:80"}},
		{name: "concrete bind untouched even with list", listen: []string{"10.0.0.9"}, bind: "192.0.2.1:443", want: []string{"192.0.2.1:443"}},
		{name: "single ip pins instance", listen: []string{"192.0.2.10"}, bind: "[::]:22", want: []string{"192.0.2.10:22"}},
		{name: "multiple ips fan out", listen: []string{"192.0.2.10", "192.0.2.11"}, bind: "[::]:443", want: []string{"192.0.2.10:443", "192.0.2.11:443"}},
		{name: "ipv6 address bracketed", listen: []string{"2001:db8::1"}, bind: "[::]:53", want: []string{"[2001:db8::1]:53"}},
		{name: "dedup + trim", listen: []string{" 192.0.2.10 ", "192.0.2.10"}, bind: "[::]:25", want: []string{"192.0.2.10:25"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := mk(tc.listen).resolveBinds(config.Listener{Bind: tc.bind})
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("resolveBinds(%q) listen=%v = %v; want %v", tc.bind, tc.listen, got, tc.want)
			}
		})
	}
}

func TestIsWildcardHost(t *testing.T) {
	wild := []string{"", "0.0.0.0", "::", "*"}
	for _, h := range wild {
		if !isWildcardHost(h) {
			t.Errorf("isWildcardHost(%q) = false; want true", h)
		}
	}
	for _, h := range []string{"10.0.0.1", "2001:db8::1", "localhost"} {
		if isWildcardHost(h) {
			t.Errorf("isWildcardHost(%q) = true; want false", h)
		}
	}
	// ifaceIPs on a bogus interface name yields nothing (no panic).
	if got := ifaceIPs([]string{"definitely-not-an-iface0"}); len(got) != 0 {
		sort.Strings(got)
		t.Errorf("ifaceIPs(bogus) = %v; want empty", got)
	}
}
