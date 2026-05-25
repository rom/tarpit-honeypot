package ui

import (
	"fmt"
	"html"
	"html/template"
	"regexp"
	"strings"
)

// renderMarkdown converts a trusted (build-time embedded) Markdown document to
// HTML for the in-product docs viewer. It supports the GitHub-flavored subset
// the project docs use: ATX headings (with slug ids so #anchor links work),
// paragraphs, fenced code blocks, unordered/ordered lists, blockquotes,
// horizontal rules, GFM tables, and inline code/bold/italic/links. Internal
// links to a doc we serve (a bare "<name>.md") are rewritten to "/docs/<name>";
// other relative links (../README.md, ../internal/…) are flattened to plain
// text since they don't resolve in-product. External http(s) links and #anchors
// are kept as-is.
//
// The input is embedded content, never attacker data, but all text is still
// HTML-escaped so code spans and angle brackets render faithfully.
func renderMarkdown(src string, served map[string]bool) template.HTML {
	lines := strings.Split(strings.ReplaceAll(src, "\r\n", "\n"), "\n")
	var b strings.Builder
	var para []string

	flushPara := func() {
		if len(para) == 0 {
			return
		}
		b.WriteString("<p>")
		b.WriteString(renderInline(strings.Join(para, " "), served))
		b.WriteString("</p>\n")
		para = para[:0]
	}

	for i := 0; i < len(lines); i++ {
		line := lines[i]
		trimmed := strings.TrimSpace(line)

		// Fenced code block.
		if strings.HasPrefix(trimmed, "```") {
			flushPara()
			lang := strings.TrimSpace(strings.TrimPrefix(trimmed, "```"))
			var code []string
			i++
			for i < len(lines) && !strings.HasPrefix(strings.TrimSpace(lines[i]), "```") {
				code = append(code, lines[i])
				i++
			}
			cls := ""
			if lang != "" {
				cls = ` class="lang-` + html.EscapeString(lang) + `"`
			}
			b.WriteString("<pre><code" + cls + ">")
			b.WriteString(html.EscapeString(strings.Join(code, "\n")))
			b.WriteString("</code></pre>\n")
			continue
		}

		// Blank line: paragraph break.
		if trimmed == "" {
			flushPara()
			continue
		}

		// Horizontal rule.
		if trimmed == "---" || trimmed == "***" || trimmed == "___" {
			flushPara()
			b.WriteString("<hr>\n")
			continue
		}

		// ATX heading.
		if m := headingRe.FindStringSubmatch(line); m != nil {
			flushPara()
			level := len(m[1])
			text := strings.TrimSpace(m[2])
			id := slugify(text)
			fmt.Fprintf(&b, "<h%d id=\"%s\">%s</h%d>\n", level, id, renderInline(text, served), level)
			continue
		}

		// Blockquote: gather consecutive '>' lines.
		if strings.HasPrefix(trimmed, ">") {
			flushPara()
			var quote []string
			for i < len(lines) {
				t := strings.TrimSpace(lines[i])
				if !strings.HasPrefix(t, ">") {
					break
				}
				quote = append(quote, strings.TrimPrefix(strings.TrimPrefix(t, ">"), " "))
				i++
			}
			i--
			b.WriteString("<blockquote>")
			b.WriteString(renderInline(strings.Join(quote, " "), served))
			b.WriteString("</blockquote>\n")
			continue
		}

		// GFM table: a header row followed by a separator row.
		if strings.Contains(line, "|") && i+1 < len(lines) && tableSepRe.MatchString(lines[i+1]) {
			flushPara()
			i = renderTable(&b, lines, i, served)
			continue
		}

		// Unordered / ordered list.
		if listItemRe.MatchString(line) || orderedItemRe.MatchString(line) {
			flushPara()
			i = renderList(&b, lines, i, served)
			continue
		}

		// Otherwise accumulate into the current paragraph.
		para = append(para, trimmed)
	}
	flushPara()
	return template.HTML(b.String()) //nolint:gosec // content is build-time embedded, fully escaped above
}

var (
	headingRe     = regexp.MustCompile(`^(#{1,6})\s+(.*?)\s*#*\s*$`)
	listItemRe    = regexp.MustCompile(`^\s*[-*+]\s+(.*)$`)
	orderedItemRe = regexp.MustCompile(`^\s*\d+\.\s+(.*)$`)
	tableSepRe    = regexp.MustCompile(`^\s*\|?[\s:|-]*-[\s:|-]*\|?\s*$`)
	codeSpanRe    = regexp.MustCompile("`[^`]+`")
	linkRe        = regexp.MustCompile(`\[([^\]]*)\]\(([^)]+)\)`)
	boldRe        = regexp.MustCompile(`\*\*([^*]+?)\*\*`)
	italicRe      = regexp.MustCompile(`\*(\S[^*\n]*?)\*`)
)

// renderList consumes a contiguous run of list items starting at index start
// and returns the index of the last consumed line. Lists are rendered flat
// (the project docs don't nest list markers outside code blocks).
func renderList(b *strings.Builder, lines []string, start int, served map[string]bool) int {
	ordered := orderedItemRe.MatchString(lines[start]) && !listItemRe.MatchString(lines[start])
	tag := "ul"
	if ordered {
		tag = "ol"
	}
	b.WriteString("<" + tag + ">\n")
	i := start
	var cur []string
	flushItem := func() {
		if cur == nil {
			return
		}
		b.WriteString("<li>")
		b.WriteString(renderInline(strings.Join(cur, " "), served))
		b.WriteString("</li>\n")
		cur = nil
	}
	for i < len(lines) {
		line := lines[i]
		if strings.TrimSpace(line) == "" {
			break
		}
		if m := listItemRe.FindStringSubmatch(line); m != nil && !orderedItemRe.MatchString(line) {
			flushItem()
			cur = []string{m[1]}
			i++
			continue
		}
		if m := orderedItemRe.FindStringSubmatch(line); m != nil {
			flushItem()
			cur = []string{m[1]}
			i++
			continue
		}
		// Indented continuation of the current item.
		if cur != nil && (strings.HasPrefix(line, "  ") || strings.HasPrefix(line, "\t")) {
			cur = append(cur, strings.TrimSpace(line))
			i++
			continue
		}
		break
	}
	flushItem()
	b.WriteString("</" + tag + ">\n")
	return i - 1
}

// renderTable consumes a GFM table starting at the header line (index start)
// and returns the index of the last consumed line.
func renderTable(b *strings.Builder, lines []string, start int, served map[string]bool) int {
	header := splitTableRow(lines[start])
	aligns := tableAligns(splitTableRow(lines[start+1]), len(header))
	b.WriteString("<table>\n<thead><tr>")
	for j, h := range header {
		b.WriteString("<th" + alignAttr(aligns, j) + ">")
		b.WriteString(renderInline(strings.TrimSpace(h), served))
		b.WriteString("</th>")
	}
	b.WriteString("</tr></thead>\n<tbody>\n")
	i := start + 2
	for i < len(lines) {
		line := lines[i]
		if !strings.Contains(line, "|") || strings.TrimSpace(line) == "" {
			break
		}
		cells := splitTableRow(line)
		b.WriteString("<tr>")
		for j := 0; j < len(header); j++ {
			cell := ""
			if j < len(cells) {
				cell = strings.TrimSpace(cells[j])
			}
			b.WriteString("<td" + alignAttr(aligns, j) + ">")
			b.WriteString(renderInline(cell, served))
			b.WriteString("</td>")
		}
		b.WriteString("</tr>\n")
		i++
	}
	b.WriteString("</tbody>\n</table>\n")
	return i - 1
}

func tableAligns(sep []string, n int) []string {
	a := make([]string, n)
	for j := 0; j < n && j < len(sep); j++ {
		c := strings.TrimSpace(sep[j])
		left := strings.HasPrefix(c, ":")
		right := strings.HasSuffix(c, ":")
		switch {
		case left && right:
			a[j] = "center"
		case right:
			a[j] = "right"
		}
	}
	return a
}

func alignAttr(a []string, j int) string {
	if j < len(a) && a[j] != "" {
		return ` style="text-align:` + a[j] + `"`
	}
	return ""
}

// splitTableRow splits a table row on unescaped pipes, honoring "\|" as a
// literal pipe (used inside code spans like `cef\|leef`), and drops the empty
// cells produced by leading/trailing pipes.
func splitTableRow(s string) []string {
	s = strings.TrimSpace(s)
	var cells []string
	var cur strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) && s[i+1] == '|' {
			cur.WriteByte('|')
			i++
			continue
		}
		if s[i] == '|' {
			cells = append(cells, cur.String())
			cur.Reset()
			continue
		}
		cur.WriteByte(s[i])
	}
	cells = append(cells, cur.String())
	// Trim the empty leading/trailing cell from edge pipes.
	if len(cells) > 0 && strings.TrimSpace(cells[0]) == "" {
		cells = cells[1:]
	}
	if len(cells) > 0 && strings.TrimSpace(cells[len(cells)-1]) == "" {
		cells = cells[:len(cells)-1]
	}
	return cells
}

// renderInline applies inline Markdown (code, links, bold, italic) to a single
// run of text, escaping everything else.
func renderInline(s string, served map[string]bool) string {
	// 1. Extract code spans first (no other inline markup applies inside).
	var codes []string
	s = codeSpanRe.ReplaceAllStringFunc(s, func(m string) string {
		inner := strings.Trim(m, "`")
		codes = append(codes, "<code>"+html.EscapeString(inner)+"</code>")
		return fmt.Sprintf("\x00c%d\x00", len(codes)-1)
	})

	// 2. Extract links before escaping (the URL needs raw handling).
	var anchors []string
	s = linkRe.ReplaceAllStringFunc(s, func(m string) string {
		sm := linkRe.FindStringSubmatch(m)
		text, url := sm[1], sm[2]
		anchors = append(anchors, renderLink(text, url, served))
		return fmt.Sprintf("\x00a%d\x00", len(anchors)-1)
	})

	// 3. Escape the remaining literal text.
	s = html.EscapeString(s)

	// 4. Bold then italic on the escaped text (the markers survive escaping).
	s = boldRe.ReplaceAllString(s, "<strong>$1</strong>")
	s = italicRe.ReplaceAllString(s, "<em>$1</em>")

	// 5. Restore links and code spans.
	for i := len(anchors) - 1; i >= 0; i-- {
		s = strings.Replace(s, fmt.Sprintf("\x00a%d\x00", i), anchors[i], 1)
	}
	for i := len(codes) - 1; i >= 0; i-- {
		s = strings.Replace(s, fmt.Sprintf("\x00c%d\x00", i), codes[i], 1)
	}
	return s
}

// renderLink builds an <a> for an internal/served doc link, an external link,
// or a same-page anchor; otherwise it flattens to the (escaped) link text since
// the target doesn't resolve in-product.
func renderLink(text, url string, served map[string]bool) string {
	etext := html.EscapeString(text)
	switch {
	case strings.HasPrefix(url, "http://"), strings.HasPrefix(url, "https://"):
		return `<a href="` + html.EscapeString(url) + `" rel="noopener noreferrer">` + etext + `</a>`
	case strings.HasPrefix(url, "#"):
		return `<a href="` + html.EscapeString(url) + `">` + etext + `</a>`
	}
	// Relative link. Only a bare "<name>.md(#anchor)" maps to a served doc.
	path, anchor := url, ""
	if h := strings.IndexByte(url, '#'); h >= 0 {
		path, anchor = url[:h], url[h:]
	}
	if !strings.Contains(path, "/") && strings.HasSuffix(path, ".md") {
		name := strings.TrimSuffix(path, ".md")
		if served[name] {
			return `<a href="/docs/` + html.EscapeString(name) + html.EscapeString(anchor) + `">` + etext + `</a>`
		}
	}
	// Not served in-product: keep the text, drop the dead link.
	return etext
}

// slugify produces a GitHub-style heading anchor id.
func slugify(s string) string {
	// Strip inline markup markers so the slug matches the rendered text.
	s = strings.ReplaceAll(s, "`", "")
	s = strings.ReplaceAll(s, "*", "")
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '_':
			b.WriteRune(r)
		case r == ' ' || r == '-':
			b.WriteByte('-')
		}
	}
	out := b.String()
	for strings.Contains(out, "--") {
		out = strings.ReplaceAll(out, "--", "-")
	}
	return strings.Trim(out, "-")
}
