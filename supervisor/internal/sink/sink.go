// Package sink writes the messages the agent produces.
//
// P1 writes newline-delimited JSON to a local file so a session can be replayed and diffed without
// a backend. P2 replaces this with the WSS uplink; the interface is deliberately narrow so that
// swap touches one file.
package sink

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
)

type Sink struct {
	mu sync.Mutex
	f  *os.File
}

func Open(path string) (*Sink, error) {
	f, err := os.Create(path)
	if err != nil {
		return nil, fmt.Errorf("open sink %q: %w", path, err)
	}
	return &Sink{f: f}, nil
}

// WriteRaw appends a message exactly as the probe produced it.
//
// Byte-preserving on purpose. Re-encoding here would change key order and escaping, and the
// evidence chain in P2 hashes the RFC 8785 canonical form of what was accepted — a supervisor that
// quietly reshapes messages in transit makes that chain unverifiable. See schemas/README.md §6.
func (s *Sink) WriteRaw(msg json.RawMessage) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.f.Write(append([]byte(msg), '\n')); err != nil {
		return err
	}
	return s.f.Sync()
}

// WriteValue appends a message the supervisor itself produced — lifecycle events.
func (s *Sink) WriteValue(v any) error {
	encoded, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("encode message: %w", err)
	}
	return s.WriteRaw(encoded)
}

func (s *Sink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.f.Close()
}
