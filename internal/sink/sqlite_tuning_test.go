package sink

import (
	"testing"
	"time"
)

func TestSQLiteTuningDefaults(t *testing.T) {
	d := SQLiteTuning{}.withDefaults()
	if d.Batch != 256 || d.Flush != 500*time.Millisecond || d.HardCap != 8192 {
		t.Errorf("zero should yield built-in defaults, got %+v", d)
	}
	o := SQLiteTuning{Batch: 10, Flush: time.Second, HardCap: 99}.withDefaults()
	if o.Batch != 10 || o.Flush != time.Second || o.HardCap != 99 {
		t.Errorf("explicit overrides not kept, got %+v", o)
	}
}
