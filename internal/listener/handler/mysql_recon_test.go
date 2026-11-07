package handler

import (
	"bytes"
	"testing"
)

func TestMySQLReconAnswer(t *testing.T) {
	cases := []struct {
		q, wantCol, wantCell string
	}{
		{"SELECT @@version", "version()", "5.7.42-log"},
		{"select user()", "user()", "root@localhost"},
		{"SHOW DATABASES", "Database", "information_schema"},
		{"select 1", "1", "1"},
	}
	for _, c := range cases {
		cols, rows, ok := mysqlReconAnswer(c.q, "5.7.42-log")
		if !ok {
			t.Errorf("mysqlReconAnswer(%q) not recognised", c.q)
			continue
		}
		if cols[0] != c.wantCol {
			t.Errorf("mysqlReconAnswer(%q) col = %q; want %q", c.q, cols[0], c.wantCol)
		}
		found := false
		for _, r := range rows {
			for _, cell := range r {
				if cell == c.wantCell {
					found = true
				}
			}
		}
		if !found {
			t.Errorf("mysqlReconAnswer(%q) rows %v missing %q", c.q, rows, c.wantCell)
		}
	}
	// A UDF-exec query is not treated as benign recon.
	if _, _, ok := mysqlReconAnswer("select sys_exec('id')", "5.7.42-log"); ok {
		t.Error("an exploit query must not be answered as recon")
	}
}

// walkPackets splits a MySQL packet stream into bodies and checks sequence ids
// increment from 1.
func walkPackets(t *testing.T, buf []byte) [][]byte {
	t.Helper()
	var bodies [][]byte
	seq := byte(1)
	for len(buf) >= 4 {
		n := int(buf[0]) | int(buf[1])<<8 | int(buf[2])<<16
		if buf[3] != seq {
			t.Errorf("packet seq = %d; want %d", buf[3], seq)
		}
		if 4+n > len(buf) {
			t.Fatalf("truncated packet: need %d, have %d", 4+n, len(buf))
		}
		bodies = append(bodies, buf[4:4+n])
		buf = buf[4+n:]
		seq++
	}
	if len(buf) != 0 {
		t.Errorf("trailing bytes after packets: %d", len(buf))
	}
	return bodies
}

func TestMySQLTextResultSetFraming(t *testing.T) {
	cols := []string{"version()"}
	rows := [][]string{{"5.7.42-log"}}

	// Classic (no DEPRECATE_EOF): colcount, 1 coldef, EOF, row, EOF = 5 packets.
	classic := mysqlTextResultSet(cols, rows, false)
	cb := walkPackets(t, classic)
	if len(cb) != 5 {
		t.Fatalf("classic result set = %d packets; want 5", len(cb))
	}
	if cb[0][0] != 0x01 { // column count = 1
		t.Errorf("column count body = %v; want 1", cb[0])
	}
	if cb[2][0] != 0xfe || cb[4][0] != 0xfe { // intermediate + final EOF
		t.Errorf("classic set should be EOF-framed: %v / %v", cb[2], cb[4])
	}
	if !bytes.Contains(cb[3], []byte("5.7.42-log")) {
		t.Errorf("row packet missing the value: %v", cb[3])
	}

	// DEPRECATE_EOF: colcount, 1 coldef, row, OK(0xFE) = 4 packets (no middle EOF).
	deprecated := mysqlTextResultSet(cols, rows, true)
	db := walkPackets(t, deprecated)
	if len(db) != 4 {
		t.Fatalf("deprecate-eof result set = %d packets; want 4", len(db))
	}
	if db[2][0] == 0xfe {
		t.Errorf("with DEPRECATE_EOF there must be no intermediate EOF before the row")
	}
	if db[3][0] != 0xfe {
		t.Errorf("terminator should be an OK/EOF header 0xFE: %v", db[3])
	}
	if !bytes.Contains(db[2], []byte("5.7.42-log")) {
		t.Errorf("row packet missing the value: %v", db[2])
	}
}

// A SQL NULL field is sent as 0xFB, not a length-encoded string.
func TestMySQLResultNullField(t *testing.T) {
	out := mysqlTextResultSet([]string{"database()"}, [][]string{{"\x00NULL"}}, true)
	bodies := walkPackets(t, out)
	// Packets: colcount, coldef, row, OK. The row is bodies[2].
	if len(bodies) != 4 || bodies[2][0] != 0xfb {
		t.Errorf("NULL field should be 0xFB; row body = %v", bodies[2])
	}
}
