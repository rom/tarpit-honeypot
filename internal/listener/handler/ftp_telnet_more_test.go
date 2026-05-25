package handler

import (
	"bufio"
	"strings"
	"testing"

	"github.com/rom/tarpit-honeypot/internal/fakefiles"
)

func TestParseNewEnviron(t *testing.T) {
	cases := []struct {
		name string
		in   []byte
		want map[string]string
	}{
		{"var-value", []byte{0, 'U', 'S', 'E', 'R', 1, 'r', 'o', 'o', 't'}, map[string]string{"USER": "root"}},
		{"var-no-value", []byte{0, 'P', 'A', 'T', 'H'}, map[string]string{"PATH": ""}},
		{"two-vars", []byte{0, 'A', 1, 'x', 0, 'B', 1, 'y'}, map[string]string{"A": "x", "B": "y"}},
		{"uservar", []byte{3, 'T', 'Z', 1, 'U', 'T', 'C'}, map[string]string{"TZ": "UTC"}},
		{"escaped-value", []byte{0, 'A', 1, 2, 0, 'b'}, map[string]string{"A": "\x00b"}},
		{"empty", []byte{}, map[string]string{}},
	}
	for _, tc := range cases {
		got := parseNewEnviron(tc.in)
		if len(got) != len(tc.want) {
			t.Errorf("%s: got %v; want %v", tc.name, got, tc.want)
			continue
		}
		for k, v := range tc.want {
			if got[k] != v {
				t.Errorf("%s: [%q]=%q; want %q", tc.name, k, got[k], v)
			}
		}
	}
}

func TestParseTelnetSubneg(t *testing.T) {
	res := &Result{Meta: map[string]any{}}
	parseTelnetSubneg([]byte{telOptTType, 0x00, 'x', 't', 'e', 'r', 'm'}, res)
	parseTelnetSubneg([]byte{telOptTSpeed, 0x00, '3', '8', '4', '0', '0'}, res)
	parseTelnetSubneg([]byte{telOptNAWS, 0x00, 0x50, 0x00, 0x18}, res) // w_hi w_lo h_hi h_lo => 80x24
	parseTelnetSubneg(append([]byte{telOptNewEnv, 0x00, 0x00}, []byte("USER")...), res)
	if res.Meta["terminal_type"] != "xterm" {
		t.Errorf("terminal_type = %v", res.Meta["terminal_type"])
	}
	if res.Meta["terminal_speed"] != "38400" {
		t.Errorf("terminal_speed = %v", res.Meta["terminal_speed"])
	}
	if res.Meta["window_size"] != "80x24" {
		t.Errorf("window_size = %v; want 80x24", res.Meta["window_size"])
	}
	env, _ := res.Meta["telnet_env"].(map[string]string)
	if _, ok := env["USER"]; !ok {
		t.Errorf("telnet_env should contain USER; got %v", env)
	}
	// Short / unknown / nil subnegs must not panic or populate.
	parseTelnetSubneg(nil, res)
	parseTelnetSubneg([]byte{telOptNAWS, 0x00}, res) // too short for NAWS
	parseTelnetSubneg([]byte{0x99, 0x00, 'z'}, res)  // unknown option
}

func TestDataCmdIP(t *testing.T) {
	cases := []struct{ cmd, arg, want string }{
		{"PORT", "192,168,1,5,200,21", "192.168.1.5"},
		{"EPRT", "|1|10.0.0.9|5001|", "10.0.0.9"},
		{"EPRT", "|2|fe80::1|5001|", "fe80::1"},
		{"PORT", "garbage", ""},
		{"EPRT", "nope", ""},
		{"EPRT", "", ""},
	}
	for _, c := range cases {
		if got := dataCmdIP(c.cmd, c.arg); got != c.want {
			t.Errorf("dataCmdIP(%q,%q) = %q; want %q", c.cmd, c.arg, got, c.want)
		}
	}
}

func TestFormatMLSD(t *testing.T) {
	dir := formatMLSD(fakefiles.File{Name: "backup", Size: 4096})
	if !strings.Contains(dir, "type=dir;") || !strings.HasSuffix(dir, " backup") {
		t.Errorf("dir MLSD = %q", dir)
	}
	file := formatMLSD(fakefiles.File{Name: "x.txt", Size: 10})
	if !strings.Contains(file, "type=file;") || !strings.Contains(file, "size=10;") {
		t.Errorf("file MLSD = %q", file)
	}
}

func TestResolveDirAndClean(t *testing.T) {
	if got := resolveDir("/", "pub"); got != "/pub" {
		t.Errorf("resolveDir(/,pub) = %q", got)
	}
	if got := resolveDir("/pub", "sub"); got != "/pub/sub" {
		t.Errorf("resolveDir(/pub,sub) = %q", got)
	}
	if got := resolveDir("/pub/sub", ".."); got != "/" {
		t.Errorf("resolveDir(.., ) = %q; want / (CDUP goes to root)", got)
	}
	if got := resolveDir("/a/b", "/etc"); got != "/etc" {
		t.Errorf("absolute CWD = %q", got)
	}
	// Traversal must be collapsed — no ".." segment can survive.
	if got := cleanDir("/a/../../etc/passwd"); got != "/etc/passwd" {
		t.Errorf("cleanDir traversal = %q; want /etc/passwd", got)
	}
	if got := joinPath("/pub", "file"); got != "/pub/file" {
		t.Errorf("joinPath = %q", got)
	}
}

// TestFTPControlCommandReplies drives the new control-channel commands and
// checks their replies. It deliberately never issues a data command after a
// PASV/EPSV (which would block on the data Accept with no client connecting).
func TestFTPControlCommandReplies(t *testing.T) {
	ctrl, wait := ftpControl(t)
	br := bufio.NewReader(ctrl)
	reply := func() string { l, _ := br.ReadString('\n'); return l }
	send := func(s string) { _, _ = ctrl.Write([]byte(s + "\r\n")) }

	reply() // 220 banner
	send("USER anonymous")
	reply()
	send("PASS x")
	reply()
	send("PASS x")
	reply() // 230 logged in

	check := func(cmd, wantPrefix string, wantContains ...string) {
		send(cmd)
		r := reply()
		if !strings.HasPrefix(r, wantPrefix) {
			t.Errorf("%q -> %q; want prefix %q", cmd, r, wantPrefix)
		}
		for _, w := range wantContains {
			if !strings.Contains(r, w) {
				t.Errorf("%q -> %q; want to contain %q", cmd, r, w)
			}
		}
	}
	check("SIZE id_rsa", "213 ")
	check("MDTM id_rsa", "213 ")
	check("SIZE nope.dat", "550")
	check("MLSD", "425") // no PASV yet
	check("STAT", "211")
	check("MKD newdir", "257", "newdir")
	check("REST 100", "350")
	check("ALLO 65536", "202")
	check("ABOR", "226")
	check("PORT 9,9,9,9,4,1", "200") // bounce target (third party)
	check("EPSV", "229", "|||")      // opens a listener; no data command follows

	send("QUIT")
	reply()
	_ = ctrl.Close()

	res := wait()
	anoms, _ := res.Meta["anomalies"].([]string)
	if !containsStr(anoms, "ftp-bounce-scan") {
		t.Errorf("PORT to a third party should flag ftp-bounce-scan; got %v", anoms)
	}
}
