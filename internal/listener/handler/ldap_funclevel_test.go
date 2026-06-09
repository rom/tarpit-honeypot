package handler

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/archetype"
	"github.com/rom/tarpit-honeypot/internal/config"
)

// The rootDSE must advertise the AD functional level (domainControllerFunctionality
// etc.) pinned by the domain-controller archetype: 2008R2->4, 2016->7.
func TestLDAPRootDSEFunctionalLevel(t *testing.T) {
	cases := map[string]string{"windows-2008r2-ad": "4", "windows-2016-ad": "7"}
	for arch, want := range cases {
		p := archetype.Lookup(arch)
		if p == nil {
			t.Fatalf("archetype %q not found", arch)
		}
		client, server := pipePair(t)
		cfg := config.Listener{Handler: "ldap", ReadTimeout: time.Second}
		done := make(chan struct{})
		go func() { defer close(done); _, _ = (&ldap{arch: p}).Handle(context.Background(), server, cfg) }()
		_, _ = client.Write(rootDSESearch(2))
		buf := make([]byte, 4096)
		_ = client.SetReadDeadline(time.Now().Add(time.Second))
		n, _ := client.Read(buf)
		_ = client.Close()
		<-done
		out := buf[:n]
		for _, attr := range []string{"domainControllerFunctionality", "forestFunctionality", "domainFunctionality", "supportedCapabilities", "isGlobalCatalogReady"} {
			if !bytes.Contains(out, []byte(attr)) {
				t.Errorf("%s: rootDSE missing %q", arch, attr)
			}
		}
		// The level value must be present (and the right one).
		if !bytes.Contains(out, []byte("domainControllerFunctionality")) || !bytes.Contains(out, []byte(want)) {
			t.Errorf("%s: rootDSE should advertise functional level %s: %q", arch, want, out)
		}
	}
}
