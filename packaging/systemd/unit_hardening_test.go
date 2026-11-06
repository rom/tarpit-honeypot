package systemd

import (
	"os"
	"strings"
	"testing"
)

// requiredDirectives are the systemd security directives every shipped unit
// must carry. A network-exposed honeypot that binds hundreds of ports is a
// prime post-exploitation pivot, so the unit is the outermost confinement
// layer and must not silently drift weaker than the one scripts/install.sh
// generates. This guards the regression where the packaged units lagged the
// install.sh-generated unit.
var requiredDirectives = []string{
	"NoNewPrivileges=true",
	"ProtectSystem=strict",
	"ReadOnlyPaths=/etc/tarpit-honeypot",
	"ProtectHome=true",
	"PrivateTmp=true",
	"PrivateDevices=true",
	"ProtectKernelTunables=true",
	"ProtectKernelModules=true",
	"ProtectKernelLogs=true",
	"ProtectControlGroups=true",
	"ProtectClock=true",
	"ProtectHostname=true",
	"ProtectProc=invisible",
	"RestrictNamespaces=true",
	"RestrictSUIDSGID=true",
	"RestrictRealtime=true",
	"RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_PACKET AF_NETLINK",
	"MemoryDenyWriteExecute=true",
	"LockPersonality=true",
	"SystemCallArchitectures=native",
	"CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_NET_RAW",
}

func TestShippedUnitsAreHardened(t *testing.T) {
	// go test runs with CWD = this package directory, so the units are siblings.
	units := []string{"tarpit-honeypot.service", "tarpit-honeypot@.service"}
	for _, u := range units {
		b, err := os.ReadFile(u)
		if err != nil {
			t.Fatalf("read %s: %v", u, err)
		}
		body := string(b)
		for _, d := range requiredDirectives {
			if !strings.Contains(body, d) {
				t.Errorf("%s is missing hardening directive %q", u, d)
			}
		}
		// A SystemCallFilter allowlist is intentionally NOT used (it would risk
		// blocking the in-process Landlock syscalls); make sure nobody adds one
		// without revisiting that decision.
		if strings.Contains(body, "SystemCallFilter=") {
			t.Errorf("%s added a SystemCallFilter — revisit the in-process-seccomp rationale before shipping it", u)
		}
	}
}
