package cli

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
)

// loggingFlags is the set of slog-related options every subcommand accepts.
// Defaults match the v0.x behavior (text + info + stderr).
type loggingFlags struct {
	level       string
	format      string
	destination string
	quiet       bool
	verbose     bool
}

// register adds the flags to the given FlagSet. Call after the
// subcommand's own flags so they show up at the end of the help.
func (l *loggingFlags) register(addStr func(*string, string, string, string), addBool func(*bool, string, bool, string)) {
	addStr(&l.level, "log-level", "info", "log level: debug | info | warn | error")
	addStr(&l.format, "log-format", "text", "log format: text | json")
	addStr(&l.destination, "log-file", "", "write logs to this file instead of stderr ('-' = stderr)")
	addBool(&l.quiet, "quiet", false, "shortcut for --log-level=error")
	addBool(&l.verbose, "verbose", false, "shortcut for --log-level=debug")
}

// apply replaces the default slog handler. Returns an io.Closer that the
// caller should defer-close if the log was redirected to a file (so the
// file is flushed cleanly on shutdown).
func (l *loggingFlags) apply() (io.Closer, error) {
	level := slog.LevelInfo
	switch strings.ToLower(l.level) {
	case "debug":
		level = slog.LevelDebug
	case "info", "":
		level = slog.LevelInfo
	case "warn", "warning":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		return nil, fmt.Errorf("--log-level: unknown %q (want debug|info|warn|error)", l.level)
	}
	// --quiet and --verbose are shortcuts; if either is set it overrides.
	if l.quiet {
		level = slog.LevelError
	}
	if l.verbose {
		level = slog.LevelDebug
	}

	var out io.Writer = os.Stderr
	var closer io.Closer
	if l.destination != "" && l.destination != "-" {
		f, err := os.OpenFile(l.destination, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
		if err != nil {
			return nil, fmt.Errorf("--log-file %s: %w", l.destination, err)
		}
		out = f
		closer = f
	}

	var h slog.Handler
	switch strings.ToLower(l.format) {
	case "json":
		h = slog.NewJSONHandler(out, &slog.HandlerOptions{Level: level})
	case "text", "":
		h = slog.NewTextHandler(out, &slog.HandlerOptions{Level: level})
	default:
		if closer != nil {
			_ = closer.Close()
		}
		return nil, fmt.Errorf("--log-format: unknown %q (want text|json)", l.format)
	}
	slog.SetDefault(slog.New(h))
	return closer, nil
}
