package filter

import (
	"testing"
	"time"
)

func TestDedupWithinWindow(t *testing.T) {
	d := NewDedup(100 * time.Millisecond)
	if !d.ShouldSend("k1") {
		t.Fatal("first send should pass")
	}
	if d.ShouldSend("k1") {
		t.Fatal("second send within window should be deduped")
	}
	if !d.ShouldSend("k2") {
		t.Fatal("different key should pass")
	}
	time.Sleep(150 * time.Millisecond)
	if !d.ShouldSend("k1") {
		t.Fatal("after window, key should pass again")
	}
}

func TestDedupDisabled(t *testing.T) {
	d := NewDedup(0)
	for i := 0; i < 5; i++ {
		if !d.ShouldSend("k") {
			t.Fatalf("dedup with 0 window should always pass (iter %d)", i)
		}
	}
}

func TestDedupNil(t *testing.T) {
	var d *Dedup
	if !d.ShouldSend("anything") {
		t.Fatal("nil dedup should pass")
	}
}
