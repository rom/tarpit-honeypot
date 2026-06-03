package handler

import (
	"strings"
	"testing"

	"github.com/rom/tarpit-honeypot/internal/config"
)

func TestWebappBranding(t *testing.T) {
	res := Result{Meta: map[string]any{}}
	brand := config.WebappBrand{Name: "Globex Secure", Tagline: "Authorized staff only.", Color: "#0b5fff", Logo: "GS"}
	out := serveWebappVariant("GET / HTTP/1.1", nil, "nginx", nil, &res, "", brand)
	for _, want := range []string{"Globex Secure", "Authorized staff only.", "#0b5fff", ">GS<"} {
		if !strings.Contains(out, want) {
			t.Errorf("branded home missing %q in: %.400s", want, out)
		}
	}
	// A bad color must NOT reach the page (falls back to a derived accent).
	res2 := Result{Meta: map[string]any{}}
	bad := config.WebappBrand{Name: "X", Color: "red;}body{display:none}"}
	out2 := serveWebappVariant("GET / HTTP/1.1", nil, "nginx", nil, &res2, "", bad)
	if strings.Contains(out2, "display:none") {
		t.Error("CSS injection via brand color reached the page")
	}
}

func TestSafeCSSColor(t *testing.T) {
	for _, c := range []string{"#fff", "#0b5fff", "red", "SteelBlue"} {
		if safeCSSColor(c) == "" {
			t.Errorf("rejected valid color %q", c)
		}
	}
	for _, c := range []string{"", "#12", "#gggggg", "red;}x", "url(x)", "javascript:1"} {
		if safeCSSColor(c) != "" {
			t.Errorf("accepted invalid color %q -> %q", c, safeCSSColor(c))
		}
	}
}
