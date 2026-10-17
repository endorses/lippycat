package upstream

import (
	"context"
	"errors"
	"sync"

	"github.com/endorses/lippycat/api/gen/data"
)

// OpenReliablePacketStream uses the committed management route and registration.
// It never establishes an independent unauthenticated destination or falls back.
func (m *Manager) OpenReliablePacketStream(ctx context.Context) (data.ReliablePacketService_StreamReliablePacketsClient, error) {
	m.mu.Lock()
	conn, generation := m.conn, m.generation
	m.mu.Unlock()
	if conn == nil || generation == nil || !generation.accepting.Load() {
		return nil, errors.New("upstream route unavailable")
	}
	streamCtx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(generation.ctx, cancel)
	stream, err := data.NewReliablePacketServiceClient(conn).StreamReliablePackets(streamCtx)
	if err != nil {
		stop()
		cancel()
		return nil, err
	}
	return &reliableGenerationStream{ReliablePacketService_StreamReliablePacketsClient: stream, cleanup: func() { stop(); cancel() }}, nil
}

type reliableGenerationStream struct {
	data.ReliablePacketService_StreamReliablePacketsClient
	once    sync.Once
	cleanup func()
}

func (s *reliableGenerationStream) CloseSend() error {
	err := s.ReliablePacketService_StreamReliablePacketsClient.CloseSend()
	s.once.Do(s.cleanup)
	return err
}
func (s *reliableGenerationStream) Recv() (*data.ReliablePacketControl, error) {
	message, err := s.ReliablePacketService_StreamReliablePacketsClient.Recv()
	if err != nil {
		s.once.Do(s.cleanup)
	}
	return message, err
}
