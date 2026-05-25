package handler

import (
	"bufio"
	"context"
	"net"
	"strconv"
	"strings"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/cve"
	"github.com/rom/tarpit-honeypot/internal/identity"
)

// elasticsearch emulates an exposed Elasticsearch HTTP API (TCP 9200).
// Unauthenticated Elasticsearch is a classic data-breach source; scanners
// hit "/" for the version banner, then "/_cat/indices", "/_cluster/health",
// "/_all/_search", etc. to enumerate and exfiltrate. We return a believable
// banner + cluster/indices/nodes metadata, flag the data-access paths, watch
// for the Groovy/MVEL scripting RCE payloads, and serve no real data.
type elasticsearch struct{ id *identity.Identity }

func (e *elasticsearch) Name() string { return "elasticsearch" }

func (e *elasticsearch) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	withTimeout(conn, cfg.ReadTimeout)
	res := Result{Meta: map[string]any{}}

	br := bufio.NewReader(conn)
	first, err := readLineCapped(br, maxLineBytes)
	if err != nil {
		res.Meta["read_err"] = err.Error()
		return res, nil
	}
	res.Payload = append(res.Payload, []byte(first)...)
	method, path := extractMethod(first), extractPath(first)
	res.Meta["http_method"] = method
	res.Meta["http_path"] = path
	// Drain the rest of the request headers (bounded), tracking
	// Content-Length so we can read a bounded request body — the Groovy /
	// MVEL scripting-RCE payloads live in a POST body to _search.
	contentLen := 0
	for i := 0; i < 64; i++ {
		line, err := readLineCapped(br, maxLineBytes)
		if err != nil || line == "\r\n" || line == "\n" {
			break
		}
		res.Payload = append(res.Payload, []byte(line)...)
		if n, ok := parseContentLength(line); ok {
			contentLen = n
		}
	}
	if contentLen > 0 {
		if contentLen > 16384 {
			contentLen = 16384
		}
		body := make([]byte, contentLen)
		if n, _ := readFull(br, body); n > 0 {
			res.Payload = append(res.Payload, body[:n]...)
		}
	}

	// CVE exploit-attempt recognition (Elasticsearch Groovy/MVEL scripting
	// RCE payloads in the request). Detection only.
	for _, rec := range cve.MatchPayload("elasticsearch", string(res.Payload)) {
		res.CVEHits = appendUnique(res.CVEHits, rec.ID)
		flagAnomaly(&res, "cve:"+rec.ID)
	}

	if marker := elasticAbuse(method, path); marker != "" {
		flagAnomaly(&res, marker)
	}

	es, lucene := "7.17.0", "8.11.1"
	if e.id != nil {
		es, lucene = e.id.ElasticVersion()
	}
	body := elasticBodyVersioned(path, es, lucene)
	resp := "HTTP/1.1 200 OK\r\n" +
		"content-type: application/json; charset=UTF-8\r\n" +
		"X-elastic-product: Elasticsearch\r\n" +
		"Content-Length: " + itoa(len(body)) + "\r\n" +
		"\r\n" + body
	_, _ = conn.Write([]byte(resp))
	res.BannerSent = "elasticsearch 200 JSON (" + es + ")"
	return res, nil
}

// elasticAbuse flags Elasticsearch recon / data-access / write paths.
func elasticAbuse(method, path string) string {
	p := strings.ToLower(path)
	switch {
	case strings.Contains(p, "_bulk") || strings.Contains(p, "_reindex") ||
		strings.Contains(p, "_snapshot") || strings.Contains(p, "_restore") ||
		((method == "PUT" || method == "POST" || method == "DELETE") && strings.Contains(p, "_security")):
		return "elasticsearch-write-attempt"
	case strings.Contains(p, "_search") || strings.Contains(p, "/_all") || strings.Contains(p, "/_msearch"):
		return "elasticsearch-data-access"
	case strings.HasPrefix(p, "/_cat") || strings.Contains(p, "_cluster/health") ||
		strings.Contains(p, "/_nodes") || strings.Contains(p, "/_cluster/state") || strings.Contains(p, "/_aliases"):
		return "elasticsearch-recon"
	}
	return ""
}

// elasticBody returns the default-version banner body for a path. Kept for
// callers/tests that don't carry a deployment identity.
func elasticBody(path string) string {
	return elasticBodyVersioned(path, "7.17.0", "8.11.1")
}

// elasticBodyVersioned returns a believable JSON body for the requested
// path, stamped with the deployment's Elasticsearch / Lucene version.
func elasticBodyVersioned(path, esVer, luceneVer string) string {
	major := esVer
	if i := strings.IndexByte(major, '.'); i > 0 {
		major = major[:i]
	}
	p := strings.ToLower(path)
	switch {
	case path == "/" || path == "":
		return `{
  "name" : "es-node-01",
  "cluster_name" : "elasticsearch",
  "cluster_uuid" : "kf9xRe2qSxOnAQ7y",
  "version" : {
    "number" : "` + esVer + `",
    "build_flavor" : "default",
    "build_type" : "tar",
    "lucene_version" : "` + luceneVer + `",
    "minimum_wire_compatibility_version" : "` + major + `.0.0",
    "minimum_index_compatibility_version" : "` + major + `.0.0"
  },
  "tagline" : "You Know, for Search"
}` + "\n"
	case strings.HasPrefix(p, "/_cat/indices"):
		return "green open .kibana_1            aBcD 1 0   12 0 24kb 24kb\n" +
			"green open filebeat-" + major + ".0 EfGh 1 1 4821 0  3mb  3mb\n" +
			"green open app-logs-000001        IjKl 1 1  932 0  1mb  1mb\n"
	case strings.HasPrefix(p, "/_cat/nodes"):
		return "127.0.0.1 12 71 0 0.10 0.08 0.05 cdfhilmrstw * es-node-01\n"
	case strings.HasPrefix(p, "/_cat"):
		return "\n"
	case strings.Contains(p, "_cluster/health"):
		return `{"cluster_name":"elasticsearch","status":"green","timed_out":false,"number_of_nodes":1,"number_of_data_nodes":1,"active_primary_shards":3,"active_shards":3,"unassigned_shards":0,"active_shards_percent_as_number":100.0}` + "\n"
	case strings.HasPrefix(p, "/_nodes"):
		return `{"_nodes":{"total":1,"successful":1,"failed":0},"cluster_name":"elasticsearch","nodes":{"aBcDeFg":{"name":"es-node-01","host":"127.0.0.1","version":"` + esVer + `","roles":["master","data","ingest"]}}}` + "\n"
	case strings.Contains(p, "_security/_authenticate"):
		return `{"username":"elastic","roles":["superuser"],"full_name":null,"email":null,"enabled":true}` + "\n"
	default:
		return `{"acknowledged":true}` + "\n"
	}
}

// parseContentLength returns the numeric value of a Content-Length: header
// line, or ok=false for any other line.
func parseContentLength(line string) (int, bool) {
	if !strings.HasPrefix(strings.ToLower(line), "content-length:") {
		return 0, false
	}
	v := strings.TrimSpace(line[len("content-length:"):])
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 {
		return 0, false
	}
	return n, true
}

// readFull reads len(buf) bytes (or until error/EOF), returning the count.
func readFull(br *bufio.Reader, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := br.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}
