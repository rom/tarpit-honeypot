package sink

import (
	"context"
	"encoding/json"
	"os"
	"sync"

	"github.com/rom/tarpit-honeypot/internal/event"
)

type stdoutSink struct {
	id  string
	mu  sync.Mutex
	enc *json.Encoder
}

func newStdout(id string) *stdoutSink {
	return &stdoutSink{id: id, enc: json.NewEncoder(os.Stdout)}
}

func (s *stdoutSink) ID() string { return s.id }

func (s *stdoutSink) Send(_ context.Context, ev *event.Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.enc.Encode(ev)
}

func (s *stdoutSink) Close() error { return nil }
