// Package pcapsink writes normalized packet envelopes to classic PCAP files.
package pcapsink

import (
	"context"
	"fmt"
	"os"
	"sync"

	"github.com/endorses/lippycat/internal/pkg/pipeline"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcapgo"
)

// Sink is a synchronous PacketSink. The file header is delayed until the first
// packet so the envelope's actual link type is retained.
type Sink struct {
	mu            sync.Mutex
	file          *os.File
	writer        *pcapgo.Writer
	headerWritten bool
	closed        bool
}

// New creates a PCAP sink at path.
func New(path string) (*Sink, error) {
	// #nosec G304 -- path is an explicit capture-output destination.
	file, err := os.Create(path)
	if err != nil {
		return nil, fmt.Errorf("create PCAP file %q: %w", path, err)
	}
	return &Sink{file: file, writer: pcapgo.NewWriter(file)}, nil
}

// HandlePacket writes one normalized envelope.
func (s *Sink) HandlePacket(ctx context.Context, env *pipeline.PacketEnvelope) pipeline.Result {
	if err := ctx.Err(); err != nil {
		return pipeline.Result{Outcome: pipeline.OutcomeShutdown, DropReason: pipeline.DropShutdown, Err: err}
	}
	if env == nil {
		return pipeline.Result{Outcome: pipeline.OutcomePermanentFailure, Err: fmt.Errorf("write PCAP packet: nil envelope")}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return pipeline.Result{Outcome: pipeline.OutcomeShutdown, DropReason: pipeline.DropShutdown, Err: fmt.Errorf("write PCAP packet: sink is closed")}
	}
	if !s.headerWritten {
		if err := s.writer.WriteFileHeader(65535, env.LinkType); err != nil {
			return pipeline.Result{Outcome: pipeline.OutcomePermanentFailure, Err: fmt.Errorf("write PCAP header: %w", err)}
		}
		s.headerWritten = true
	}
	captureInfo := gopacket.CaptureInfo{
		Timestamp:      env.CaptureTime,
		CaptureLength:  env.CaptureLength,
		Length:         env.OriginalLength,
		InterfaceIndex: int(env.Source.InterfaceIndex),
	}
	if err := s.writer.WritePacket(captureInfo, env.Data); err != nil {
		return pipeline.Result{Outcome: pipeline.OutcomePermanentFailure, Err: fmt.Errorf("write PCAP packet: %w", err)}
	}
	return pipeline.Result{Outcome: pipeline.OutcomeAccepted}
}

// Close closes the destination and is idempotent.
func (s *Sink) Close(context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	if err := s.file.Close(); err != nil {
		return fmt.Errorf("close PCAP file: %w", err)
	}
	return nil
}

var _ pipeline.PacketSink = (*Sink)(nil)
