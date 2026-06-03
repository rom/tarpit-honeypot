package handler

import (
	"bufio"
	"context"
	"net"
	"strings"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/safe"
)

// svn emulates an Apache Subversion svnserve server (RFC-less S-expression
// protocol, TCP 3690). The server greets first with its protocol version +
// capability set; the client answers by selecting a version, listing its
// capabilities, and naming the repository URL it wants — which is the recon
// signal we capture. We never serve a repository; after the client's first
// command we record it and close.
type svn struct{}

func (s *svn) Name() string { return "svn" }

func (s *svn) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	withTimeout(conn, cfg.ReadTimeout)
	res := Result{Meta: map[string]any{}}
	// svnserve greeting: ( success ( min-ver max-ver ( mech... ) ( cap... ) ) )
	const greeting = "( success ( 2 2 ( ) ( edit-pipeline svndiff1 absent-entries commit-revprops depth log-revprops atomic-revprops partial-replay inherited-props ) ) ) "
	if _, err := conn.Write([]byte(greeting)); err != nil {
		res.Meta["write_err"] = err.Error()
		return res, nil
	}
	res.BannerSent = "svnserve greeting (2.2)"

	br := bufio.NewReader(conn)
	cap := cfg.ReadBytes
	if cap <= 0 || cap > 8192 {
		cap = 4096
	}
	buf := make([]byte, cap)
	n, _ := br.Read(buf)
	if n > 0 {
		raw := buf[:n]
		res.Payload = append([]byte(nil), raw...)
		res.Meta["svn_client"] = safe.SanitizeForLog(string(raw))
		// The client's response carries the repository URL it is reaching for.
		if i := strings.Index(string(raw), "svn://"); i >= 0 {
			url := string(raw[i:])
			if sp := strings.IndexAny(url, " )\r\n"); sp > 0 {
				url = url[:sp]
			}
			res.Meta["svn_repo_url"] = safe.SanitizeForLog(url)
			flagAnomaly(&res, "svn-repo-access")
		}
	}
	return res, nil
}
