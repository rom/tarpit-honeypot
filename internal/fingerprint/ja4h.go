package fingerprint

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

// JA4H produces the JA4H HTTP-client fingerprint from a raw HTTP request
// (request line + headers, ending with \r\n\r\n).
//
// Format (per the upstream spec):
//
//	t<v>h<m1><m2><n_headers><c>_<header_hash>_<cookie_field_hash>_<cookie_value_hash>
//
// Where:
//
//	v = http version digits (10, 11, 20)
//	m1m2 = first 2 chars of the lowercased method
//	n_headers = count of headers (excluding Cookie and Referer)
//	c = "c" if Cookie present, else "n"
//	header_hash = first 12 hex of sha256 over the header-name list (sorted,
//	              lowercase, Cookie+Referer excluded)
//	cookie_field_hash = first 12 hex of sha256 over the sorted cookie names
//	cookie_value_hash = first 12 hex of sha256 over the sorted cookie name=value pairs
//
// Returns ("", "") on parse failure so callers can silently skip.
func JA4H(raw []byte) (full, hash string) {
	if len(raw) == 0 {
		return "", ""
	}
	lines := strings.Split(string(raw), "\r\n")
	if len(lines) == 0 {
		return "", ""
	}
	parts := strings.Fields(lines[0])
	if len(parts) < 3 {
		return "", ""
	}
	method := strings.ToLower(parts[0])
	version := httpVersionDigits(parts[2])
	if len(method) < 2 {
		method += "_"
	}

	var headerNames []string
	cookieField := ""
	hasCookie := false
	for _, line := range lines[1:] {
		if line == "" {
			break
		}
		idx := strings.IndexByte(line, ':')
		if idx < 0 {
			continue
		}
		name := strings.ToLower(strings.TrimSpace(line[:idx]))
		value := strings.TrimSpace(line[idx+1:])
		if name == "cookie" {
			cookieField = value
			hasCookie = true
			continue
		}
		if name == "referer" {
			continue
		}
		headerNames = append(headerNames, name)
	}

	sort.Strings(headerNames)
	headerJoined := strings.Join(headerNames, ",")
	headerHash := sha256Trunc(headerJoined, 12)

	cookieFields := []string{}
	cookieValues := []string{}
	if hasCookie {
		for _, c := range strings.Split(cookieField, ";") {
			c = strings.TrimSpace(c)
			if c == "" {
				continue
			}
			if eq := strings.IndexByte(c, '='); eq >= 0 {
				cookieFields = append(cookieFields, c[:eq])
				cookieValues = append(cookieValues, c)
			} else {
				cookieFields = append(cookieFields, c)
				cookieValues = append(cookieValues, c)
			}
		}
		sort.Strings(cookieFields)
		sort.Strings(cookieValues)
	}
	cookieFieldHash := sha256Trunc(strings.Join(cookieFields, ","), 12)
	cookieValueHash := sha256Trunc(strings.Join(cookieValues, ","), 12)

	cFlag := "n"
	if hasCookie {
		cFlag = "c"
	}
	nHdr := boundedCount(len(headerNames))
	prefix := fmt.Sprintf("t%sh%s%s%s%s", version, method[:2], nHdr, cFlag, " ")
	prefix = strings.TrimSpace(prefix)
	full = fmt.Sprintf("%s_%s_%s_%s", prefix, headerHash, cookieFieldHash, cookieValueHash)
	sum := sha256.Sum256([]byte(full))
	return full, hex.EncodeToString(sum[:])[:24]
}

func httpVersionDigits(v string) string {
	switch v {
	case "HTTP/1.0":
		return "10"
	case "HTTP/1.1":
		return "11"
	case "HTTP/2", "HTTP/2.0":
		return "20"
	case "HTTP/3":
		return "30"
	}
	return "00"
}
