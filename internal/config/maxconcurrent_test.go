package config

import "testing"

// applyDefaults must give every TCP listener a concurrency ceiling unless the
// operator opted out with a negative value, so the shipped default can't run a
// listener with unbounded accepted connections. UDP listeners are untouched
// (they have no accept semaphore).
func TestListenerMaxConcurrentDefault(t *testing.T) {
	c := &Config{
		Sensor: Sensor{DataDir: "/tmp/x"},
		Listeners: []Listener{
			{ID: "unset", Proto: "tcp", Bind: "0.0.0.0:21"},                       // 0 → default
			{ID: "explicit", Proto: "tcp", Bind: "0.0.0.0:22", MaxConcurrent: 16}, // kept
			{ID: "optout", Proto: "tcp", Bind: "0.0.0.0:23", MaxConcurrent: -1},   // unlimited, kept
			{ID: "udp", Proto: "udp", Bind: "0.0.0.0:53"},                         // untouched
		},
	}
	c.applyDefaults()

	byID := map[string]int{}
	for _, l := range c.Listeners {
		byID[l.ID] = l.MaxConcurrent
	}
	if byID["unset"] != defaultListenerMaxConcurrent {
		t.Errorf("unset TCP max_concurrent = %d; want default %d", byID["unset"], defaultListenerMaxConcurrent)
	}
	if byID["explicit"] != 16 {
		t.Errorf("explicit max_concurrent = %d; want 16 (unchanged)", byID["explicit"])
	}
	if byID["optout"] != -1 {
		t.Errorf("opt-out max_concurrent = %d; want -1 (unchanged)", byID["optout"])
	}
	if byID["udp"] != 0 {
		t.Errorf("udp max_concurrent = %d; want 0 (untouched)", byID["udp"])
	}
}
