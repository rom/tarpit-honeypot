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
	mode    string
	lit     []byte         // prefix / contains literal
	rx      *regexp.Regexp // regex
	hexPfx  string         // hex_prefix, lowercased
	resp    []byte
	anomaly string
	close   bool
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
		cr := scriptedRule{mode: r.Match, resp: resp, anomaly: r.Anomaly, close: r.Close}
		switch r.Match {
		case "prefix", "contains":
			cr.lit = []byte(r.Value)
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
			if r := s.match(in); r != nil {
				matched++
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
	return res, nil
}

// match returns the first rule whose pattern matches in, or nil.
func (s *scriptedH) match(in []byte) *scriptedRule {
	var hexIn string
	for i := range s.rules {
		r := &s.rules[i]
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
