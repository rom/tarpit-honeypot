package handler

import (
	"testing"
)

func boltHandshake(first [4]byte) []byte {
	out := []byte{0x60, 0x60, 0xB0, 0x17}
	out = append(out, first[:]...)
	return append(out, make([]byte, 12)...) // three zero version slots
}

func boltHello(scheme, principal, credentials string) []byte {
	m := boltMap("user_agent", "drv/1.0", "scheme", scheme, "principal", principal, "credentials", credentials)
	return boltChunk(append([]byte{0xB1, 0x01}, m...))
}

func boltRun(query string) []byte {
	body := []byte{0xB3, 0x10} // RUN: query, params, metadata
	body = append(body, boltString(query)...)
	body = append(body, 0xA0, 0xA0) // empty params + metadata maps
	return boltChunk(body)
}

var boltGoodbye = boltChunk([]byte{0xB1, 0x02})

// The default neo4j/neo4j login carried in HELLO is captured and flagged.
func TestNeo4jBoltDefaultCredential(t *testing.T) {
	input := boltHandshake([4]byte{0, 0, 0, 5})
	input = append(input, boltHello("basic", "neo4j", "neo4j")...)
	input = append(input, boltGoodbye...)

	res, out := roundtrip(t, &neo4j{}, string(input))
	if res.Meta["auth_user"] != "neo4j" || res.Meta["auth_pass"] != "neo4j" {
		t.Errorf("credentials not captured: user=%v pass=%v", res.Meta["auth_user"], res.Meta["auth_pass"])
	}
	if !hasAnom(res, "neo4j-credential-attempt") || !hasAnom(res, "neo4j-default-login") {
		t.Errorf("credential/default not flagged: %v", res.Meta["anomalies"])
	}
	if len(out) < 4 || out[3] != 0x05 { // chosen Bolt version reply (5.0)
		t.Errorf("version reply wrong: % x", out[:min(4, len(out))])
	}
}

// A non-default login is captured but not flagged as the default.
func TestNeo4jBoltNonDefault(t *testing.T) {
	input := boltHandshake([4]byte{0, 0, 4, 4})
	input = append(input, boltHello("basic", "admin", "S3cret!")...)
	input = append(input, boltGoodbye...)

	res, _ := roundtrip(t, &neo4j{}, string(input))
	if res.Meta["auth_user"] != "admin" || res.Meta["auth_pass"] != "S3cret!" {
		t.Errorf("credentials not captured: user=%v pass=%v", res.Meta["auth_user"], res.Meta["auth_pass"])
	}
	if hasAnom(res, "neo4j-default-login") {
		t.Errorf("non-default login wrongly flagged as default")
	}
}

// A Cypher RUN after login is captured.
func TestNeo4jBoltQueryCapture(t *testing.T) {
	input := boltHandshake([4]byte{0, 0, 0, 5})
	input = append(input, boltHello("basic", "neo4j", "neo4j")...)
	input = append(input, boltRun("MATCH (n) RETURN n LIMIT 10")...)
	input = append(input, boltGoodbye...)

	res, _ := roundtrip(t, &neo4j{}, string(input))
	if res.Meta["cypher_query"] != "MATCH (n) RETURN n LIMIT 10" {
		t.Errorf("cypher not captured: %v", res.Meta["cypher_query"])
	}
	if !hasAnom(res, "neo4j-query") {
		t.Errorf("query not flagged: %v", res.Meta["anomalies"])
	}
}

// A non-Bolt opener is rejected without a crash. The input is exactly the
// 20-byte handshake the handler reads (net.Pipe writes block on unread bytes).
func TestNeo4jNonBolt(t *testing.T) {
	res, _ := roundtrip(t, &neo4j{}, "XXXXXXXXXXXXXXXXXXXX") // 20 bytes, not the Bolt magic
	if res.Meta["non_bolt"] != true {
		t.Errorf("non-bolt opener not detected: %v", res.Meta)
	}
}
