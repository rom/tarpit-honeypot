package handler

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func rethinkMagic() []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, rethinkV1Magic)
	return b
}

// The SCRAM client-first message leaks the username; client-final leaks the
// proof. Both are captured; the login is rejected.
func TestRethinkDBScramCapture(t *testing.T) {
	clientFirst := `{"protocol_version":0,"authentication_method":"SCRAM-SHA-256","authentication":"n,,n=admin,r=clientnonce"}` + "\x00"
	clientFinal := `{"authentication":"c=biws,r=clientnonceservernonce,p=cHJvb2Y="}` + "\x00"
	input := append(rethinkMagic(), clientFirst...)
	input = append(input, clientFinal...)

	res, out := roundtrip(t, &rethinkdb{}, string(input))
	if res.Meta["auth_user"] != "admin" {
		t.Errorf("username not captured: %v", res.Meta["auth_user"])
	}
	if !hasAnom(res, "rethinkdb-credential-attempt") {
		t.Errorf("credential attempt not flagged: %v", res.Meta["anomalies"])
	}
	if res.Meta["scram_proof"] != "cHJvb2Y=" {
		t.Errorf("SCRAM proof not captured: %v", res.Meta["scram_proof"])
	}
	if !bytes.Contains(out, []byte("server_version")) {
		t.Errorf("server-version document not sent")
	}
	if !bytes.Contains(out, []byte(`"authentication":"r=clientnonce`)) {
		t.Errorf("SCRAM server challenge not sent (or nonce not echoed): %q", out)
	}
}

// A non-RethinkDB opener (wrong magic) is rejected without a crash.
func TestRethinkDBWrongMagic(t *testing.T) {
	res, _ := roundtrip(t, &rethinkdb{}, "HTTP") // 4 bytes, not the V1_0 magic
	if res.Meta["non_rethinkdb"] != true {
		t.Errorf("wrong-magic opener not detected: %v", res.Meta)
	}
}
