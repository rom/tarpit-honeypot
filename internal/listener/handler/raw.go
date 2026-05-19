package handler

import (
	"context"
	"io"
	"net"

	"github.com/rom/tarpit-honeypot/internal/config"
)

type raw struct{}

func (r *raw) Name() string { return "raw" }

func (r *raw) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	withTimeout(conn, cfg.ReadTimeout)
	res := Result{}
	if cfg.Banner != "" {
		if _, err := conn.Write([]byte(cfg.Banner)); err != nil {
			res.Meta = map[string]any{"write_err": err.Error()}
		}
		res.BannerSent = cfg.Banner
	}
	if cfg.ReadBytes > 0 {
		buf := make([]byte, cfg.ReadBytes)
		n, err := io.ReadFull(conn, buf)
		if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
			if res.Meta == nil {
				res.Meta = map[string]any{}
			}
			res.Meta["read_err"] = err.Error()
		}
		if n > 0 {
			res.Payload = append([]byte{}, buf[:n]...)
		}
	}
	return res, nil
}
