package handler

import (
	"bufio"
	"context"
	"net"
	"strings"

	"github.com/rom/tarpit-honeypot/internal/config"
)

// elasticsearch emulates an exposed Elasticsearch HTTP API (TCP 9200).
// Unauthenticated Elasticsearch is a classic data-breach source; scanners
// hit "/" for the version banner, then "/_cat/indices", "/_cluster/health",
// "/_all/_search", etc. to enumerate and exfiltrate. We return a believable
// banner, flag the data-access paths, and serve no real data.
type elasticsearch struct{}

func (e *elasticsearch) Name() string { return "elasticsearch" }

func (e *elasticsearch) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	withTimeout(conn, cfg.ReadTimeout)
	res := Result{Meta: map[string]any{}}

	br := bufio.NewReader(conn)
	first, err := br.ReadString('\n')
	if err != nil {
		res.Meta["read_err"] = err.Error()
		return res, nil
	}
	res.Payload = append(res.Payload, []byte(first)...)
	method, path := extractMethod(first), extractPath(first)
	res.Meta["http_method"] = method
	res.Meta["http_path"] = path
	// Drain the rest of the request headers (bounded).
	for i := 0; i < 64; i++ {
		line, err := br.ReadString('\n')
		if err != nil || line == "\r\n" || line == "\n" {
			break
		}
		res.Payload = append(res.Payload, []byte(line)...)
	}

	if marker := elasticAbuse(path); marker != "" {
		flagAnomaly(&res, marker)
	}

	body := elasticBody(path)
	resp := "HTTP/1.1 200 OK\r\n" +
		"content-type: application/json; charset=UTF-8\r\n" +
		"X-elastic-product: Elasticsearch\r\n" +
		"Content-Length: " + itoa(len(body)) + "\r\n" +
		"\r\n" + body
	_, _ = conn.Write([]byte(resp))
	res.BannerSent = "elasticsearch 200 JSON"
	return res, nil
}

// elasticAbuse flags Elasticsearch recon / data-access request paths.
func elasticAbuse(path string) string {
	p := strings.ToLower(path)
	switch {
	case strings.Contains(p, "_search") || strings.Contains(p, "/_all") || strings.Contains(p, "/_msearch"):
		return "elasticsearch-data-access"
	case strings.HasPrefix(p, "/_cat") || strings.Contains(p, "_cluster/health") ||
		strings.Contains(p, "/_nodes") || strings.Contains(p, "/_cluster/state") || strings.Contains(p, "/_aliases"):
		return "elasticsearch-recon"
	}
	return ""
}

// elasticBody returns a believable JSON body for the requested path.
func elasticBody(path string) string {
	switch {
	case path == "/" || path == "":
		return `{
  "name" : "es-node-01",
  "cluster_name" : "elasticsearch",
  "cluster_uuid" : "na",
  "version" : {
    "number" : "7.17.0",
    "build_flavor" : "default",
    "lucene_version" : "8.11.1"
  },
  "tagline" : "You Know, for Search"
}` + "\n"
	case strings.HasPrefix(path, "/_cat"):
		return "\n"
	default:
		return `{"acknowledged":true}` + "\n"
	}
}
