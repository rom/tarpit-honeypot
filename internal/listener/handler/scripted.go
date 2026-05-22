package handler

import (
	"bytes"
	"context"
	"encoding/hex"
	"net"
	"regexp"
	"strings"

	"github.com/rom/tarpit-honeypot/internal/config"
)

// scriptedH is the compiled form of a config.ScriptedProto: a declarative
// request/response state machine that stands up a believable custom TCP
// service without writing Lua. On connect it sends an optional greeting,
// then matches each client message top-down against the rules and writes
// the first match's response. See config.ScriptedProto for the YAML surface.
type scriptedH struct {
	greeting  []byte
	rules     []scriptedRule
	deflt     []byte
	maxRounds int
}

type scriptedRule struct {
	mode     string
	lit      []byte         // prefix / contains / suffix literal
	litLower []byte         // lower-cased literal for the i-variants
	rx       *regexp.Regexp // regex
	hexPfx   string         // hex_prefix, lowercased
	resp     []byte
	anomaly  string
	close    bool
	stage    string // required current stage ("" = any)
	setStage string // stage to transition to on match
	capture  string // "user" | "pass" | ""
}

func (s *scriptedH) Name() string { return "scripted" }

// scriptedMaxTranscript bounds how much attacker input we retain per
// connection regardless of read_bytes / max_rounds.
const scriptedMaxTranscript = 16 * 1024

// compileScripted turns a ScriptedProto into a scriptedH. It re-runs
// Validate first so a handler built outside the config loader (tests,
// honeynet expansion) still rejects a malformed spec; decode errors can't
// then occur, so the DecodeScriptedField results are used directly.
func compileScripted(p config.ScriptedProto) (*scriptedH, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	greet, _ := config.DecodeScriptedField(p.Greeting, p.GreetingHex)
	deflt, _ := config.DecodeScriptedField(p.Default, p.DefaultHex)
	h := &scriptedH{greeting: greet, deflt: deflt, maxRounds: p.MaxRounds}
	if h.maxRounds <= 0 {
		h.maxRounds = 8
	}
	for _, r := range p.Rules {
		resp, _ := config.DecodeScriptedField(r.Respond, r.RespondHex)
		cr := scriptedRule{
			mode: r.Match, resp: resp, anomaly: r.Anomaly, close: r.Close,
			stage: r.Stage, setStage: r.SetStage, capture: r.Capture,
		}
		switch r.Match {
		case "prefix", "contains", "suffix":
			cr.lit = []byte(r.Value)
		case "iprefix", "icontains":
			cr.litLower = []byte(strings.ToLower(r.Value))
		case "regex":
			cr.rx = regexp.MustCompile(r.Value) // Validate already compiled it
		case "hex_prefix":
			cr.hexPfx = strings.ToLower(strings.TrimSpace(r.Value))
		}
		h.rules = append(h.rules, cr)
	}
	return h, nil
}

func (s *scriptedH) Handle(ctx context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	withTimeout(conn, cfg.ReadTimeout)
	res := Result{Meta: map[string]any{}}
	if len(s.greeting) > 0 {
		if _, err := conn.Write(s.greeting); err != nil {
			res.Meta["write_err"] = err.Error()
			return res, nil
		}
		res.BannerSent = string(s.greeting)
	}
	readCap := cfg.ReadBytes
	if readCap <= 0 || readCap > 65535 {
		readCap = 4096
	}
	buf := make([]byte, readCap)
	var transcript []byte
	matched := 0
	stage := "" // session stage for stateful, multi-step protocols
	for i := 0; i < s.maxRounds; i++ {
		n, err := conn.Read(buf)
		if n > 0 {
			in := buf[:n]
			if room := scriptedMaxTranscript - len(transcript); room > 0 {
				if n > room {
					transcript = append(transcript, in[:room]...)
				} else {
					transcript = append(transcript, in...)
				}
			}
			if r := s.match(in, stage); r != nil {
				matched++
				if r.capture != "" && r.rx != nil {
					scriptedCapture(&res, r, in)
				}
				if r.setStage != "" {
					stage = r.setStage
				}
				if len(r.resp) > 0 {
					if _, werr := conn.Write(r.resp); werr != nil {
						break
					}
				}
				if r.anomaly != "" {
					flagAnomaly(&res, r.anomaly)
				}
				if r.close {
					break
				}
			} else if len(s.deflt) > 0 {
				if _, werr := conn.Write(s.deflt); werr != nil {
					break
				}
			}
		}
		if err != nil {
			break
		}
	}
	res.Payload = transcript
	res.Meta["scripted_matches"] = matched
	if stage != "" {
		res.Meta["scripted_stage"] = stage
	}
	return res, nil
}

// scriptedCapture pulls the first regex capture group out of in and records
// it as the named credential, feeding default-credential matching once both
// halves are present.
func scriptedCapture(res *Result, r *scriptedRule, in []byte) {
	m := r.rx.FindSubmatch(in)
	if len(m) < 2 {
		return
	}
	val := string(m[1])
	switch r.capture {
	case "user":
		res.Meta["auth_user"] = val
	case "pass":
		res.Meta["auth_pass"] = val
	}
	u, _ := res.Meta["auth_user"].(string)
	p, _ := res.Meta["auth_pass"].(string)
	if u != "" && p != "" {
		flagDefaultCred(res, u, p)
	}
}

// match returns the first rule whose pattern matches in within the current
// session stage, or nil. A rule with no Stage matches in any stage.
func (s *scriptedH) match(in []byte, stage string) *scriptedRule {
	var hexIn string
	lowerIn := bytes.ToLower(in)
	for i := range s.rules {
		r := &s.rules[i]
		if r.stage != "" && r.stage != stage {
			continue
		}
		switch r.mode {
		case "any":
			return r
		case "prefix":
			if bytes.HasPrefix(in, r.lit) {
				return r
			}
		case "contains":
			if bytes.Contains(in, r.lit) {
				return r
			}
		case "suffix":
			if bytes.HasSuffix(bytes.TrimRight(in, "\r\n"), r.lit) {
				return r
			}
		case "iprefix":
			if bytes.HasPrefix(lowerIn, r.litLower) {
				return r
			}
		case "icontains":
			if bytes.Contains(lowerIn, r.litLower) {
				return r
			}
		case "regex":
			if r.rx.Match(in) {
				return r
			}
		case "hex_prefix":
			if hexIn == "" {
				hexIn = hex.EncodeToString(in)
			}
			if strings.HasPrefix(hexIn, r.hexPfx) {
				return r
			}
		}
	}
	return nil
}
