//go:build hunter || all

// Package packetforwarding adapts authenticated durable raw transport to the
// hunter's existing generation lifecycle and flow control.
package packetforwarding

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/internal/pkg/packetreceipt"
	"github.com/endorses/lippycat/internal/pkg/packetspool"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
)

type Stream struct {
	data.ReliablePacketService_StreamReliablePacketsClient
	spool        *packetspool.Spool
	identity     *data.RawPacketIdentity
	verifier     *packetreceipt.Verifier
	mu           sync.Mutex
	expected     *data.PacketBatch
	losses       *data.ReliablePacketMessage
	lossSnapshot packetspool.LossCoverage
	acked        uint64
	lossAcked    uint64
	changed      chan struct{}
	ready        bool
	cancel       context.CancelFunc
}

func Open(ctx context.Context, conn grpc.ClientConnInterface, spool *packetspool.Spool, verifier *packetreceipt.Verifier) (*Stream, error) {
	ctx, cancel := context.WithCancel(ctx)
	stream, err := data.NewReliablePacketServiceClient(conn).StreamReliablePackets(ctx, grpc.MaxCallRecvMsgSize(1<<20))
	if err != nil {
		cancel()
		return nil, err
	}
	id := spool.Identity()
	identity := &data.RawPacketIdentity{SourceId: id.SourceID, ProducerSessionId: id.SessionID, CaptureEpoch: id.CaptureEpoch, DestinationId: id.DestinationID, AckScope: id.AckScope}
	if err := packetreceipt.ValidIdentity(identity); err != nil {
		cancel()
		closeErr := stream.CloseSend()
		return nil, errors.Join(err, closeErr)
	}
	return &Stream{ReliablePacketService_StreamReliablePacketsClient: stream, spool: spool, identity: identity, verifier: verifier, changed: make(chan struct{}, 1), cancel: cancel}, nil
}

// A stalled HTTP/2 sender must release its generation just like a missing
// receipt. Cancel the RPC itself so Send returns before the owner tears down.
func (s *Stream) boundedSend(timeout time.Duration, send func() error) error {
	timer := time.AfterFunc(timeout, s.cancel)
	defer timer.Stop()
	return send()
}

func (s *Stream) Send(batch *data.PacketBatch) error {
	if batch.Sequence == 0 && len(batch.Packets) == 0 {
		return s.ReliablePacketService_StreamReliablePacketsClient.Send(&data.ReliablePacketMessage{ProtocolVersion: 1, Identity: s.identity})
	}
	if batch.HunterId != s.identity.SourceId || batch.ProducerSessionId != s.identity.ProducerSessionId || batch.CaptureEpoch != s.identity.CaptureEpoch {
		return errors.New("durable raw batch producer identity mismatch")
	}
	s.mu.Lock()
	s.expected = proto.Clone(batch).(*data.PacketBatch)
	s.mu.Unlock()
	return s.ReliablePacketService_StreamReliablePacketsClient.Send(&data.ReliablePacketMessage{ProtocolVersion: 1, Identity: s.identity, Batch: batch})
}

func (s *Stream) Recv() (*data.StreamControl, error) {
	control, err := s.ReliablePacketService_StreamReliablePacketsClient.Recv()
	if err != nil {
		return nil, err
	}
	if control.ProtocolVersion != 1 || !proto.Equal(control.Identity, s.identity) || control.Control == nil {
		return nil, errors.New("raw receipt transport contract mismatch")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	receipt := control.Receipt
	if !s.ready {
		if err := s.verifier.Verify(receipt, s.identity, nil); err != nil {
			return nil, err
		}
		if receipt.Sequence != 0 || receipt.LossGeneration != 0 || receipt.Retired || len(receipt.Losses) > 0 || len(receipt.ContentSha256) > 0 {
			return nil, errors.New("invalid durable raw stream readiness")
		}
		s.ready = true
		return control.Control, nil
	}
	if receipt == nil {
		return nil, errors.New("durable raw transport omitted receipt")
	}
	if receipt.Sequence > 0 {
		if s.expected == nil || receipt.Sequence != s.expected.Sequence {
			return nil, errors.New("unexpected durable raw receipt sequence")
		}
		if err := s.verifier.Verify(receipt, s.identity, s.expected); err != nil {
			return nil, err
		}
		if err := s.spool.Ack(s.identity.SourceId, s.identity.ProducerSessionId, s.identity.DestinationId, s.identity.AckScope, receipt.Sequence); err != nil {
			return nil, fmt.Errorf("commit verified raw receipt: %w", err)
		}
		s.acked = receipt.Sequence
		s.expected = nil
	} else {
		if err := s.verifier.Verify(receipt, s.identity, nil); err != nil {
			return nil, err
		}
		if s.losses == nil || receipt.LossGeneration != s.losses.LossGeneration || !sameLosses(receipt.Losses, s.losses.Losses) {
			return nil, errors.New("unexpected durable raw loss receipt")
		}
		if err := s.spool.AckLossCoverage(s.identity.SourceId, s.identity.ProducerSessionId, s.identity.DestinationId, s.identity.AckScope, s.lossSnapshot); err != nil {
			return nil, err
		}
		s.lossAcked = receipt.LossGeneration
		s.losses = nil
	}
	select {
	case s.changed <- struct{}{}:
	default:
	}
	return control.Control, nil
}

func sameLosses(a, b []*data.RawPacketLossRange) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !proto.Equal(a[i], b[i]) {
			return false
		}
	}
	return true
}

func (s *Stream) waitReceipt(ctx context.Context, sequence, loss uint64) error {
	for {
		s.mu.Lock()
		ready := sequence > 0 && s.acked >= sequence || loss > 0 && s.lossAcked >= loss
		s.mu.Unlock()
		if ready {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-s.changed:
		}
	}
}

// SendNext holds at most one batch, publishes loss-only progress even when no
// packets remain, and never retires data on Send or connection replacement.
func (s *Stream) SendNext(ctx context.Context, wait func(context.Context) error, receiptTimeout time.Duration) (uint64, error) {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		losses, err := s.spool.PendingLosses()
		if err != nil {
			return 0, err
		}
		if len(losses.Ranges) > 0 {
			message := &data.ReliablePacketMessage{ProtocolVersion: 1, Identity: s.identity, LossGeneration: losses.Version}
			for _, r := range losses.Ranges {
				message.Losses = append(message.Losses, &data.RawPacketLossRange{First: r.First, Last: r.Last})
			}
			s.mu.Lock()
			s.losses = message
			s.lossSnapshot = losses
			s.mu.Unlock()
			if err := s.boundedSend(receiptTimeout, func() error { return s.ReliablePacketService_StreamReliablePacketsClient.Send(message) }); err != nil {
				return 0, err
			}
			ackCtx, cancel := context.WithTimeout(ctx, receiptTimeout)
			err = s.waitReceipt(ackCtx, 0, losses.Version)
			cancel()
			if err != nil {
				return 0, err
			}
		}
		batches, err := s.spool.BatchesAfter(0, 1)
		if err != nil {
			return 0, err
		}
		if len(batches) > 0 {
			if err := wait(ctx); err != nil {
				return 0, err
			}
			batch := batches[0]
			if !s.spool.Contains(batch.Sequence) {
				continue
			}
			if err := s.boundedSend(receiptTimeout, func() error { return s.Send(batch) }); err != nil {
				return 0, err
			}
			ackCtx, cancel := context.WithTimeout(ctx, receiptTimeout)
			err = s.waitReceipt(ackCtx, batch.Sequence, 0)
			cancel()
			if err != nil {
				return 0, err
			}
			return uint64(len(batch.Packets)), nil
		}
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		case <-ticker.C:
		}
	}
}
