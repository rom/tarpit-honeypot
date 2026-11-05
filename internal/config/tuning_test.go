package config

import (
	"testing"
	"time"
)

func TestTuningValidate(t *testing.T) {
	if err := (Tuning{}).validate(); err != nil {
		t.Errorf("zero tuning should be valid (all defaults): %v", err)
	}
	ok := Tuning{StoreMaxOpenConns: 32, SinkBatch: 500, SinkFlush: time.Second, SinkHardCap: 16384,
		UIDashboardTTL: time.Minute, UIScanLimit: 50000}
	if err := ok.validate(); err != nil {
		t.Errorf("valid overrides rejected: %v", err)
	}
	bad := []Tuning{
		{StoreMaxOpenConns: -1},
		{UIScanLimit: -5},
		{UIWindowCacheTTL: -time.Second},
		{SinkBatch: 1000, SinkHardCap: 500}, // hard cap below batch
	}
	for i, b := range bad {
		if err := b.validate(); err == nil {
			t.Errorf("case %d: expected validation error, got nil", i)
		}
	}
}
