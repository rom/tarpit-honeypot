package handler

import (
	"bufio"
	"bytes"
	"context"
	"net"
	"strings"

	"github.com/rom/tarpit-honeypot/internal/config"
)

// xmpp handles inbound XMPP client connections on TCP 5222. RFC 6120
// opens with a client <?xml version=...?><stream:stream ...> stanza
// announcing the JID/host the client wants to talk to; we capture the
// requested @to host + xmlns + version, then reply with our own
// stream:stream + a STARTTLS feature so the scanner records us as a
// real Prosody / ejabberd server. Then we wait for either a <auth>
// PLAIN mechanism (credentials) or a stream close.
type xmpp struct{}

func (x *xmpp) Name() string { return "xmpp" }

func (x *xmpp) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	withTimeout(conn, cfg.ReadTimeout)
	res := Result{Meta: map[string]any{}}
	br := bufio.NewReader(conn)

	cap := cfg.ReadBytes
	if cap <= 0 {
		cap = 4096
	}
	// Read until we see "<stream:stream" + ">". The client sends a
	// non-self-closing element, so we just look for the closing '>'.
	var buf bytes.Buffer
	for buf.Len() < cap {
		b, err := br.ReadByte()
		if err != nil {
			res.Meta["read_err"] = err.Error()
			break
		}
		buf.WriteByte(b)
		if b == '>' && bytes.Contains(buf.Bytes(), []byte("<stream:stream")) {
			break
		}
	}
	res.Payload = append([]byte(nil), buf.Bytes()...)
	open := buf.String()
	res.Meta["client_open"] = open
	res.Meta["to"] = xmppAttr(open, "to")
	res.Meta["from"] = xmppAttr(open, "from")
	res.Meta["xmlns"] = xmppAttr(open, "xmlns")
	res.Meta["version"] = xmppAttr(open, "version")

	streamHost := xmppAttr(open, "to")
	if streamHost == "" {
		streamHost = "im.example.com"
	}
	reply := `<?xml version='1.0'?>` +
		`<stream:stream from='` + streamHost + `' id='deadbeef' version='1.0' xml:lang='en' ` +
		`xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client'>` +
		`<stream:features>` +
		`<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>` +
		`<mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>` +
		`<mechanism>PLAIN</mechanism><mechanism>SCRAM-SHA-1</mechanism></mechanisms>` +
		`</stream:features>`
	if _, err := conn.Write([]byte(reply)); err != nil {
		res.Meta["write_err"] = err.Error()
		return res, nil
	}
	res.BannerSent = "xmpp stream:features"

	// Try to read one more stanza to capture either <starttls/> or
	// <auth mechanism=PLAIN>...</auth>.
	var next bytes.Buffer
	depth := 0
	for next.Len() < cap {
		b, err := br.ReadByte()
		if err != nil {
			break
		}
		next.WriteByte(b)
		if b == '<' {
			depth++
		}
		if b == '>' {
			s := next.Bytes()
			// Closing-element heuristic: ends with "/>" or
			// "</something>".
			if len(s) >= 2 && (s[len(s)-2] == '/' || (depth > 1 && bytes.Contains(s, []byte("</")))) {
				break
			}
			if next.Len() > 4 && depth == 1 && bytes.HasPrefix(s, []byte("<auth")) && bytes.HasSuffix(s, []byte("</auth>")) {
				break
			}
		}
	}
	res.Payload = append(res.Payload, next.Bytes()...)
	if next.Len() > 0 {
		res.Meta["client_second"] = next.String()
		if bytes.Contains(next.Bytes(), []byte("<starttls")) {
			res.Meta["wants_starttls"] = true
			// Send a fake success then close — the scanner records
			// us as a TLS-supporting server even though we don't
			// negotiate.
			_, _ = conn.Write([]byte(`<proceed xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>`))
		} else if bytes.Contains(next.Bytes(), []byte("<auth")) {
			res.Meta["auth_attempt"] = next.String()
			// SASL failure so the scanner sees "this is a real
			// server that rejected my creds".
			_, _ = conn.Write([]byte(`<failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><not-authorized/></failure>`))
		}
	}
	_, _ = conn.Write([]byte(`</stream:stream>`))
	return res, nil
}

// xmppAttr extracts a single XML attribute value from an open-stream
// element. It's deliberately simple — XMPP attributes use single or
// double quotes and don't contain escaped quotes in practice for the
// values we care about (to / from / xmlns / version).
func xmppAttr(s, key string) string {
	idx := strings.Index(s, key+"=")
	if idx < 0 {
		return ""
	}
	rest := s[idx+len(key)+1:]
	if len(rest) == 0 {
		return ""
	}
	quote := rest[0]
	if quote != '\'' && quote != '"' {
		return ""
	}
	end := strings.IndexByte(rest[1:], quote)
	if end < 0 {
		return ""
	}
	return rest[1 : 1+end]
}
