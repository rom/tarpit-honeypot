package handler

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// Recon queries get a believable single-row answer so the attacker keeps going.
func TestPgReconAnswer(t *testing.T) {
	cases := []struct {
		q, wantCol, wantSub string
	}{
		{"SELECT version()", "version", "PostgreSQL 14.11"},
		{"select current_user", "current_user", "postgres"},
		{"SELECT current_database()", "current_database", "postgres"},
		{"show data_directory", "data_directory", "/var/lib/postgresql"},
		{"SELECT 1", "?column?", "1"},
	}
	for _, c := range cases {
		col, val, ok := pgReconAnswer(c.q, "14.11")
		if !ok {
			t.Errorf("pgReconAnswer(%q) not recognised", c.q)
			continue
		}
		if col != c.wantCol || !bytes.Contains([]byte(val), []byte(c.wantSub)) {
			t.Errorf("pgReconAnswer(%q) = (%q,%q); want col %q containing %q", c.q, col, val, c.wantCol, c.wantSub)
		}
	}
	// A non-recon query is not answered with a row.
	if _, _, ok := pgReconAnswer("COPY x FROM PROGRAM 'id'", "14.11"); ok {
		t.Error("an exploit query must not be treated as benign recon")
	}
}

// pgSimpleResult frames a valid RowDescription + DataRow + CommandComplete.
func TestPgSimpleResultFraming(t *testing.T) {
	out := pgSimpleResult("version", "PostgreSQL 14.11")
	// First message must be RowDescription 'T' with a correct length prefix.
	if out[0] != 'T' {
		t.Fatalf("first message = %q; want RowDescription 'T'", out[0])
	}
	tlen := int(binary.BigEndian.Uint32(out[1:5]))
	// 'T' body contains fieldCount(2). Walk to the next message and confirm it's
	// a DataRow 'D', then a CommandComplete 'C'.
	next := 1 + tlen
	if next >= len(out) || out[next] != 'D' {
		t.Fatalf("second message not DataRow 'D' at %d: %q", next, out[next:])
	}
	dlen := int(binary.BigEndian.Uint32(out[next+1 : next+5]))
	cc := next + 1 + dlen
	if cc >= len(out) || out[cc] != 'C' {
		t.Fatalf("third message not CommandComplete 'C' at %d", cc)
	}
	if !bytes.Contains(out, []byte("PostgreSQL 14.11")) {
		t.Error("value not present in DataRow")
	}
	if !bytes.Contains(out, []byte("SELECT 1")) {
		t.Error("CommandComplete tag should be SELECT 1")
	}
}
