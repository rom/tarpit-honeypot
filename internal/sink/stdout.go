package sink

import (
	"context"
	"os"
	"sync"

	"github.com/rom/tarpit-honeypot/internal/event"
	"github.com/rom/tarpit-honeypot/internal/format"
)

type stdoutSink struct {
	id        string
	formatter format.Formatter
	mu        sync.Mutex
}

func newStdout(id string, f format.Formatter) *stdoutSink {
	return &stdoutSink{id: id, formatter: f}
}

func (s *stdoutSink) ID() string { return s.id }

func (s *stdoutSink) Send(_ context.Context, ev *event.Event) error {
	b, err := s.formatter.Format(ev)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := os.Stdout.Write(append(b, '\n')); err != nil {
		return err
	}
	return nil
}

func (s *stdoutSink) Close() error { return nil }
