package cli

import (
	"archive/zip"
	"io"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteDocxCanaryIsValidZipWithCallback(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bait.docx")
	callback := "http://oob.canary.example.com/doc/deadbeef-prod"
	if err := writeDocxCanary(path, callback); err != nil {
		t.Fatalf("writeDocxCanary: %v", err)
	}

	zr, err := zip.OpenReader(path)
	if err != nil {
		t.Fatalf("generated file is not a valid zip/docx: %v", err)
	}
	defer zr.Close()

	want := map[string]bool{
		"[Content_Types].xml":          false,
		"_rels/.rels":                  false,
		"word/document.xml":            false,
		"word/_rels/document.xml.rels": false,
		"word/settings.xml":            false,
	}
	var relsBody string
	for _, f := range zr.File {
		if _, ok := want[f.Name]; ok {
			want[f.Name] = true
		}
		if f.Name == "word/_rels/document.xml.rels" {
			rc, err := f.Open()
			if err != nil {
				t.Fatal(err)
			}
			b, _ := io.ReadAll(rc)
			rc.Close()
			relsBody = string(b)
		}
	}
	for name, present := range want {
		if !present {
			t.Errorf("docx missing required part %q", name)
		}
	}

	// The external attachedTemplate relationship must carry the callback URL
	// with TargetMode="External" — that's what beacons on open.
	if !strings.Contains(relsBody, callback) {
		t.Errorf("callback URL not embedded in document rels:\n%s", relsBody)
	}
	if !strings.Contains(relsBody, `TargetMode="External"`) {
		t.Errorf("relationship not marked External (won't beacon):\n%s", relsBody)
	}
	if !strings.Contains(relsBody, "attachedTemplate") {
		t.Errorf("expected an attachedTemplate relationship:\n%s", relsBody)
	}
}

func TestWriteDocxCanaryEscapesURL(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "x.docx")
	// A URL with XML-significant characters must be escaped so the part stays
	// well-formed.
	if err := writeDocxCanary(path, "http://h/doc/a&b<c>"); err != nil {
		t.Fatal(err)
	}
	zr, err := zip.OpenReader(path)
	if err != nil {
		t.Fatalf("not valid zip after escaping: %v", err)
	}
	defer zr.Close()
	for _, f := range zr.File {
		if f.Name == "word/_rels/document.xml.rels" {
			rc, _ := f.Open()
			b, _ := io.ReadAll(rc)
			rc.Close()
			if strings.Contains(string(b), "a&b<c>") {
				t.Errorf("URL not XML-escaped in rels: %s", b)
			}
			if !strings.Contains(string(b), "a&amp;b&lt;c&gt;") {
				t.Errorf("expected escaped URL in rels: %s", b)
			}
		}
	}
}
