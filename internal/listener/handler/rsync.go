package handler

import (
	"bufio"
	"context"
	"net"
	"strings"

	"github.com/rom/tarpit-honeypot/internal/config"
)

// rsyncH emulates an rsync daemon (TCP 873). A real daemon greets with
// "@RSYNCD: <version>"; the client echoes a version then either "#list"
// (enumerate modules) or a module name to access. Exposed rsync daemons
// are a classic data-exfil / backup-theft finding, so we advertise a
// believable module, capture the request, and flag the enumeration /
// access — but never serve any files.
type rsyncH struct{}

func (rsyncH) Name() string { return "rsync" }

func (rsyncH) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	withTimeout(conn, cfg.ReadTimeout)
	res := Result{Meta: map[string]any{}}

	if _, err := conn.Write([]byte("@RSYNCD: 31.0\n")); err != nil {
		res.Meta["write_err"] = err.Error()
		return res, nil
	}
	res.BannerSent = "@RSYNCD: 31.0"

	br := bufio.NewReader(conn)
	line, _ := br.ReadString('\n')
	line = strings.TrimRight(line, "\r\n")
	res.Payload = append([]byte(nil), []byte(line)...)
	res.Meta["rsync_request"] = line

	// The client first sends its own "@RSYNCD: <ver>" line; read the
	// following module request (best-effort).
	if strings.HasPrefix(line, "@RSYNCD:") {
		mod, _ := br.ReadString('\n')
		mod = strings.TrimRight(mod, "\r\n")
		res.Payload = append(res.Payload, []byte("\n"+mod)...)
		line = mod
		res.Meta["rsync_module_request"] = mod
	}

	switch {
	case line == "" || line == "#list":
		_, _ = conn.Write([]byte("backups       \tNightly backup share\nshares        \tDepartment file shares\n@RSYNCD: EXIT\n"))
		res.BannerSent = "rsync module list"
		flagAnomaly(&res, "rsync-module-list")
	default:
		// Access to a named module — demand auth (capture the attempt).
		_, _ = conn.Write([]byte("@RSYNCD: AUTHREQD 7Hj2Kd9\n"))
		res.Meta["rsync_module"] = line
		flagAnomaly(&res, "rsync-module-access")
	}
	return res, nil
}
