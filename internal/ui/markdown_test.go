package ui

import (
	"strings"
	"testing"

	tdocs "github.com/rom/tarpit-honeypot/docs"
)

func TestRenderMarkdownBasics(t *testing.T) {
	served := map[string]bool{"fleet": true}
	src := strings.Join([]string{
		"# Title",
		"",
		"A paragraph with `code`, **bold**, *italic*, and a [link](fleet.md#9-troubleshooting).",
		"",
		"## Section 2",
		"",
		"- one",
		"- two",
		"",
		"```yaml",
		"key: <value> & more",
		"```",
		"",
		"| A | B |",
		"|---|--:|",
		"| `cef\\|leef` | 2 |",
		"",
		"> a note",
		"",
		"---",
	}, "\n")

	out := string(renderMarkdown(src, served))

	wants := []string{
		`<h1 id="title">Title</h1>`,
		`<code>code</code>`,
		`<strong>bold</strong>`,
		`<em>italic</em>`,
		`<a href="/docs/fleet#9-troubleshooting">link</a>`,
		`<h2 id="section-2">Section 2</h2>`,
		"<ul>",
		"<li>one</li>",
		`<pre><code class="lang-yaml">`,
		"key: &lt;value&gt; &amp; more",
		"<table>",
		`<th style="text-align:right">B</th>`,
		"<code>cef|leef</code>",
		"<blockquote>a note</blockquote>",
		"<hr>",
	}
	for _, w := range wants {
		if !strings.Contains(out, w) {
			t.Errorf("rendered output missing %q\n---\n%s", w, out)
		}
	}
}

func TestRenderLinkFlattensUnservedRelative(t *testing.T) {
	served := map[string]bool{}
	out := string(renderMarkdown("see [the readme](../README.md) and [internals](internals.md).", served))
	if strings.Contains(out, "href=\"../README.md\"") {
		t.Errorf("unserved relative link should be flattened: %s", out)
	}
	if !strings.Contains(out, "the readme") {
		t.Errorf("flattened link should keep its text: %s", out)
	}
	// internals.md isn't in served, so it flattens too (text kept, no anchor).
	if strings.Contains(out, `href="/docs/internals"`) {
		t.Errorf("internals not served, should not link: %s", out)
	}
}

// TestAllEmbeddedDocsRender ensures every shipped doc renders without panic and
// produces non-trivial HTML, and that the curated catalog only names real docs.
func TestAllEmbeddedDocsRender(t *testing.T) {
	served := availableDocs()
	if len(served) == 0 {
		t.Fatal("no docs embedded")
	}
	for name := range served {
		raw, err := tdocs.FS.ReadFile(name + ".md")
		if err != nil {
			t.Errorf("read %s: %v", name, err)
			continue
		}
		out := string(renderMarkdown(string(raw), served))
		if len(out) < 50 {
			t.Errorf("doc %s rendered too short (%d bytes)", name, len(out))
		}
	}
	for _, d := range docCatalog {
		if !served[d.Name] {
			t.Errorf("catalog names %q but no docs/%s.md is embedded", d.Name, d.Name)
		}
	}
}
