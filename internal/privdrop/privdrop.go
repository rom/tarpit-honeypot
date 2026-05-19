// Package privdrop drops the process to an unprivileged uid/gid after
// privileged setup (binding low ports, opening data dirs, etc.).
//
// Linux implementation lives in privdrop_linux.go. Other platforms fall
// back to a stub that errors with a clear message — Windows service
// integration in v0.4 will provide an equivalent path.
package privdrop

import "errors"

// ErrNotSupported is returned by Drop on platforms without a real
// implementation (currently anything not linux).
var ErrNotSupported = errors.New("privdrop: not supported on this platform")
