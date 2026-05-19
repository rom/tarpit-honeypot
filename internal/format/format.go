// Package format serializes events into the wire formats SIEMs expect.
// The default JSON formatter is what every sink used through v1.3; the
// CEF, LEEF, and OCSF formatters are opt-in via the channel's format
// field for ArcSight / QRadar / cloud-SIEM integrations.
package format

import (
	"encoding/json"
	"fmt"

	"github.com/rom/tarpit-honeypot/internal/event"
)

const (
	Vendor    = "tarpit-honeypot"
	Product   = "tarpit"
	ProductVN = "1.4"
)

// Formatter is the contract every sink can call to produce wire bytes
// from an event. Returns an error only when the underlying encoder
// genuinely fails — formatters never refuse on missing optional fields.
type Formatter interface {
	Format(ev *event.Event) ([]byte, error)
	Name() string
	ContentType() string
}

// Get returns the formatter for the named format. Unknown names error;
// empty falls back to JSON for backward compatibility.
func Get(name string) (Formatter, error) {
	switch name {
	case "", "json":
		return &jsonF{}, nil
	case "cef":
		return &cefF{}, nil
	case "leef":
		return &leefF{}, nil
	case "ocsf":
		return &ocsfF{}, nil
	}
	return nil, fmt.Errorf("unknown format %q (want json | cef | leef | ocsf)", name)
}

type jsonF struct{}

func (j *jsonF) Name() string        { return "json" }
func (j *jsonF) ContentType() string { return "application/json" }
func (j *jsonF) Format(ev *event.Event) ([]byte, error) {
	return json.Marshal(ev)
}
