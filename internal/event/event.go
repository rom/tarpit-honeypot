package event

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"
)

type Severity int

const (
	SeverityLow Severity = iota + 1
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

func ParseSeverity(s string) (Severity, error) {
	switch s {
	case "low":
		return SeverityLow, nil
	case "medium", "med":
		return SeverityMedium, nil
	case "high":
		return SeverityHigh, nil
	case "critical", "crit":
		return SeverityCritical, nil
	}
	return 0, fmt.Errorf("unknown severity %q", s)
}

func (s Severity) String() string {
	switch s {
	case SeverityLow:
		return "low"
	case SeverityMedium:
		return "medium"
	case SeverityHigh:
		return "high"
	case SeverityCritical:
		return "critical"
	}
	return "unknown"
}

func (s Severity) MarshalJSON() ([]byte, error) {
	return []byte(`"` + s.String() + `"`), nil
}

func (s *Severity) UnmarshalJSON(b []byte) error {
	if len(b) >= 2 && b[0] == '"' && b[len(b)-1] == '"' {
		v, err := ParseSeverity(string(b[1 : len(b)-1]))
		if err != nil {
			return err
		}
		*s = v
		return nil
	}
	// Tolerate raw numeric form (older logs, hand-crafted events).
	n := 0
	for _, c := range b {
		if c < '0' || c > '9' {
			return fmt.Errorf("severity: cannot parse %s", b)
		}
		n = n*10 + int(c-'0')
	}
	*s = Severity(n)
	return nil
}

type Endpoint struct {
	IP   string `json:"ip"`
	Port int    `json:"port,omitempty"`
}

type Event struct {
	ID            string         `json:"id"`
	Time          time.Time      `json:"time"`
	Sensor        string         `json:"sensor"`
	RuleID        string         `json:"rule_id"`
	Severity      Severity       `json:"severity"`
	Source        Endpoint       `json:"source"`
	Dest          Endpoint       `json:"dest"`
	Proto         string         `json:"proto"`
	Handler       string         `json:"handler,omitempty"`
	BannerSent    string         `json:"banner_sent,omitempty"`
	PayloadBase64 string         `json:"payload_b64,omitempty"`
	PayloadLen    int            `json:"payload_len,omitempty"`
	Meta          map[string]any `json:"meta,omitempty"`

	// MitreTechniques lists the MITRE ATT&CK technique IDs (e.g.
	// "T1190", "T1110.001") attributable to the activity that
	// produced this event. Set by the router from a rule_id ->
	// techniques mapping; downstream sinks include the IDs verbatim
	// for SIEM-side ATT&CK pivot.
	MitreTechniques []string `json:"mitre_techniques,omitempty"`
	// MitreTactics lists the high-level tactic names (e.g.
	// "discovery", "initial-access", "credential-access") that the
	// techniques fall under. Used by the storyline correlator to
	// detect tactic-transition sequences from a single source.
	MitreTactics []string `json:"mitre_tactics,omitempty"`
	// Anomalies lists protocol-misuse markers the handler flagged
	// (e.g. "ssh-banner-non-printable", "http-method-unknown") so a
	// SIEM rule can route them separately from normal triggers.
	Anomalies []string `json:"anomalies,omitempty"`
}

func NewID() string {
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		// rand.Read failing is a fatal-class problem; emit a timestamp-derived
		// fallback so we still get *some* unique-ish id and the caller can
		// continue. We never expect this branch in practice.
		t := time.Now().UnixNano()
		for i := 0; i < len(b); i++ {
			b[i] = byte(t >> (8 * (i % 8)))
		}
	}
	return hex.EncodeToString(b[:])
}
