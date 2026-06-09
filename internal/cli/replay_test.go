package cli

import (
	"reflect"
	"testing"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/identity"
	"github.com/rom/tarpit-honeypot/internal/jitter"
	"github.com/rom/tarpit-honeypot/internal/listener/handler"
)

func TestDriveHandlerHTTPOffline(t *testing.T) {
	deps := handler.Deps{Identity: identity.New("test"), Jitter: jitter.New(0, 0)}
	req := []byte("GET /../../etc/passwd HTTP/1.1\r\nHost: x\r\nUser-Agent: sqlmap/1.7\r\n\r\n")
	res, err := driveHandler("http", false, req, deps, config.Listener{Handler: "http", Mode: "banner"})
	if err != nil {
		t.Fatal(err)
	}
	anoms, _ := res.Meta["anomalies"].([]string)
	want := map[string]bool{"tool:sqlmap": false, "uri-path-traversal": false}
	for _, a := range anoms {
		if _, ok := want[a]; ok {
			want[a] = true
		}
	}
	for a, seen := range want {
		if !seen {
			t.Errorf("expected anomaly %q in replay result, got %v", a, anoms)
		}
	}
}

func TestDiffSets(t *testing.T) {
	add, drop := diffSets([]string{"a", "b"}, []string{"b", "c"})
	if !reflect.DeepEqual(add, []string{"c"}) || !reflect.DeepEqual(drop, []string{"a"}) {
		t.Fatalf("diffSets wrong: added=%v removed=%v", add, drop)
	}
	if a, d := diffSets([]string{"x"}, []string{"x"}); len(a) != 0 || len(d) != 0 {
		t.Errorf("identical sets should diff empty, got %v %v", a, d)
	}
}
