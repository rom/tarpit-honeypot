package version

// Version is overridden at build time via -ldflags (see the Makefile,
// which derives it from `git describe`). The compiled-in default is the
// current release series so a plain `go build` / `go install` reports a
// meaningful version.
var (
	Version   = "2.12.0"
	Commit    = "unknown"
	BuildDate = "unknown"
)
