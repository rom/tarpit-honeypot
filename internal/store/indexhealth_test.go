package store

import "testing"

func TestIndexHealth(t *testing.T) {
	s, err := Open(t.TempDir(), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	// Open ran ensureIndexes, so nothing should be missing.
	if miss := s.MissingIndexes(); len(miss) != 0 {
		t.Fatalf("fresh store has missing indexes: %v", miss)
	}
	// The new dst_ip index must exist.
	have := false
	rows, _ := s.db.Query(`SELECT name FROM sqlite_master WHERE type='index' AND name='idx_events_dst_ip_time'`)
	for rows.Next() {
		have = true
	}
	rows.Close()
	if !have {
		t.Error("idx_events_dst_ip_time not created")
	}
	// Drop one and confirm MissingIndexes detects it + EnsureIndexes heals it.
	if _, err := s.db.Exec(`DROP INDEX idx_events_dst_ip_time`); err != nil {
		t.Fatal(err)
	}
	if miss := s.MissingIndexes(); len(miss) != 1 || miss[0] != "idx_events_dst_ip_time" {
		t.Fatalf("MissingIndexes after drop = %v; want [idx_events_dst_ip_time]", miss)
	}
	if s.EnsureIndexes(); len(s.MissingIndexes()) != 0 {
		t.Errorf("EnsureIndexes did not heal the dropped index: %v", s.MissingIndexes())
	}
}
