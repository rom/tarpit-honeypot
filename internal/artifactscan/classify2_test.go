package artifactscan

import (
	"archive/zip"
	"bytes"
	"testing"
)

func TestNewClassificationRules(t *testing.T) {
	e := NewEngine()
	cases := []struct{ rule, data string }{
		{"Private_Key_Material", "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXk\n"},
		{"Private_Key_Material", "-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n"},
		{"Private_Key_Material", "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAB user@host"},
		{"WEBSHELL_ASP_Classic", "<%eval request(\"cmd\")%>"},
		{"WEBSHELL_ASP_Classic", "set s = server.createobject(\"wscript.shell\"): s.run \"cmd.exe /c calc\""},
	}
	for _, c := range cases {
		if !hasMatch(e.Scan([]byte(c.data)), c.rule) {
			t.Errorf("%s should match %q; got %v", c.rule, c.data, matchNames(e.Scan([]byte(c.data))))
		}
	}
}

func TestAnalyzeArchiveExecutable(t *testing.T) {
	// (a) a member whose real magic is PE, regardless of its name.
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, _ := zw.Create("invoice.pdf")
	_, _ = w.Write(append([]byte("MZ"), bytes.Repeat([]byte{0}, 80)...))
	_ = zw.Close()
	r := Analyze(buf.Bytes())
	if !r.ArchiveExecutable {
		t.Errorf("PE-by-magic member not detected as archive executable: %+v", r.Suspicious)
	}

	// (b) a member with an executable extension.
	buf.Reset()
	zw = zip.NewWriter(&buf)
	w, _ = zw.Create("setup.exe")
	_, _ = w.Write([]byte("not really a pe but named exe"))
	_ = zw.Close()
	r = Analyze(buf.Bytes())
	if !r.ArchiveExecutable || r.ArchiveExecutableName != "setup.exe" {
		t.Errorf("exe-by-extension not detected: exe=%v name=%q", r.ArchiveExecutable, r.ArchiveExecutableName)
	}

	// (c) a benign archive is not flagged.
	buf.Reset()
	zw = zip.NewWriter(&buf)
	w, _ = zw.Create("readme.txt")
	_, _ = w.Write([]byte("hello"))
	_ = zw.Close()
	if Analyze(buf.Bytes()).ArchiveExecutable {
		t.Error("benign archive wrongly flagged")
	}
}
