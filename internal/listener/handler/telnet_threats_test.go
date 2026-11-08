package handler

import "testing"

func TestTelnetEncryptOverflow(t *testing.T) {
	res := &Result{Meta: map[string]any{}}
	sub := append([]byte{telOptEncl}, make([]byte, 200)...) // ENCRYPT suboption, over-long
	parseTelnetSubneg(sub, res)
	if !hasAnom(*res, "telnet-encrypt-overflow") || !hasAnom(*res, "cve:CVE-2011-4862") {
		t.Errorf("ENCRYPT overflow not flagged: %v", res.Meta["anomalies"])
	}
}

func TestTelnetEnvInjection(t *testing.T) {
	res := &Result{Meta: map[string]any{}}
	// NEW-ENVIRON IS: VAR "LD_PRELOAD" VALUE "/tmp/x.so"
	body := []byte{telOptNewEnv, 0x00, 0x00}
	body = append(body, []byte("LD_PRELOAD")...)
	body = append(body, 0x01)
	body = append(body, []byte("/tmp/x.so")...)
	parseTelnetSubneg(body, res)
	if !hasAnom(*res, "telnet-env-injection") {
		t.Errorf("env injection not flagged: %v", res.Meta["anomalies"])
	}
}

func TestTelnetMiraiAndBusybox(t *testing.T) {
	if !telnetMiraiCredential("root", "xc3511") {
		t.Error("Mirai credential root:xc3511 not recognized")
	}
	if telnetMiraiCredential("alice", "s3cret-unique") {
		t.Error("ordinary credential wrongly flagged as Mirai")
	}
	if !telnetBusyboxProbe("/bin/busybox MIRAI") || !telnetBusyboxProbe("enable") {
		t.Error("busybox/enable probe not recognized")
	}
}

func TestTelnetSolarisFBypassAndZyxelBackdoor(t *testing.T) {
	for _, u := range []string{"-froot", "-f bin", "-l -froot", "-l-fbin"} {
		if !telnetSolarisFBypass(u) {
			t.Errorf("Solaris -f bypass not recognized for %q", u)
		}
	}
	for _, u := range []string{"root", "admin", "-rf", "file-f"} {
		if telnetSolarisFBypass(u) {
			t.Errorf("ordinary login %q wrongly flagged as -f bypass", u)
		}
	}
	if !telnetZyxelSuBackdoor("zyad5001") || !telnetZyxelSuBackdoor("su zyad5001") {
		t.Error("ZyXEL su backdoor password not recognized")
	}
	if telnetZyxelSuBackdoor("s3cret") {
		t.Error("ordinary password wrongly flagged as ZyXEL backdoor")
	}
}
