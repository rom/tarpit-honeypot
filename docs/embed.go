// Package docs embeds the project's Markdown documentation so the web UI can
// render it in-product (the "docs" tab) without shipping the files separately.
// The man page (tarpit-honeypot.1) is intentionally excluded — only the .md
// guides are embedded.
package docs

import "embed"

// FS holds every Markdown document under docs/, compiled into the binary.
//
//go:embed *.md
var FS embed.FS
