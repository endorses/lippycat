package upstream

import (
	"context"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/failover"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

type candidateService struct {
	management.UnimplementedManagementServiceServer
	data.UnimplementedDataServiceServer
	data.UnimplementedRelayDataServiceServer
	relayVersion  uint32
	relayReject   bool
	relayHang     bool
	relayBatches  chan *data.PacketBatch
	registration  *management.ProcessorRegistrationResponse
	registrations atomic.Int64
	batches       atomic.Int64
	hang          bool
}

func (s *candidateService) RegisterProcessor(ctx context.Context, _ *management.ProcessorRegistration) (*management.ProcessorRegistrationResponse, error) {
	s.registrations.Add(1)
	if s.hang {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	if s.registration != nil {
		return proto.Clone(s.registration).(*management.ProcessorRegistrationResponse), nil
	}
	return &management.ProcessorRegistrationResponse{Accepted: true, RawRelayVersion: s.relayVersion, UpstreamProcessorId: "test-upstream", AcceptedForwardingMode: management.ForwardingMode_FORWARDING_MODE_PACKETS}, nil
}
func (s *candidateService) StreamPackets(stream data.DataService_StreamPacketsServer) error {
	for {
		batch, err := stream.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		s.batches.Add(1)
		if err := stream.Send(&data.StreamControl{AckSequence: batch.Sequence}); err != nil {
			return err
		}
	}
}
func startCandidate(t *testing.T, service *candidateService) (string, *grpc.Server) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	server := grpc.NewServer()
	management.RegisterManagementServiceServer(server, service)
	data.RegisterDataServiceServer(server, service)
	data.RegisterRelayDataServiceServer(server, service)
	go func() {
		if err := server.Serve(listener); err != nil {
			t.Logf("test candidate server ended: %v", err)
		}
	}()
	t.Cleanup(server.Stop)
	return listener.Addr().String(), server
}
func fastFailover() failover.Config {
	return failover.Config{AttemptTimeout: 100 * time.Millisecond, ReconnectAttempts: 1, RetryInitial: 10 * time.Millisecond, RetryMax: 20 * time.Millisecond}
}

func TestUpstreamSkipsStalledRegistrationAndStaysOnWorkingCandidate(t *testing.T) {
	stalled := &candidateService{hang: true}
	first, _ := startCandidate(t, stalled)
	healthy := &candidateService{}
	second, _ := startCandidate(t, healthy)
	m := NewManager(Config{Endpoints: []failover.Endpoint{{Address: first}, {Address: second}}, Failover: fastFailover(), ProcessorID: "relay", ListenAddress: "localhost:55555"}, nil)
	require.NoError(t, m.Start())
	defer m.Disconnect()
	require.Eventually(t, func() bool { return m.ActiveAddress() == second && m.IsConnected() }, 3*time.Second, time.Millisecond)
	m.Forward(&data.PacketBatch{Sequence: 1, Packets: []*data.CapturedPacket{{}}})
	require.Eventually(t, func() bool { return healthy.batches.Load() == 1 }, time.Second, time.Millisecond)
	firstAttempts := stalled.registrations.Load()
	time.Sleep(150 * time.Millisecond)
	require.Equal(t, firstAttempts, stalled.registrations.Load(), "a working secondary remains active")
}

func TestUpstreamChangesGenerationAfterServerFailure(t *testing.T) {
	firstService := &candidateService{}
	first, server := startCandidate(t, firstService)
	secondService := &candidateService{}
	second, _ := startCandidate(t, secondService)
	m := NewManager(Config{Endpoints: []failover.Endpoint{{Address: first}, {Address: second}}, Failover: fastFailover(), ProcessorID: "relay", ListenAddress: "localhost:55555"}, nil)
	require.NoError(t, m.Start())
	defer m.Disconnect()
	require.Eventually(t, func() bool { return m.ActiveAddress() == first }, time.Second, time.Millisecond)
	m.mu.Lock()
	old := m.generation
	m.mu.Unlock()
	server.Stop()
	require.Eventually(t, func() bool { return m.ActiveAddress() == second }, 3*time.Second, time.Millisecond)
	require.ErrorIs(t, old.ctx.Err(), context.Canceled)
	m.mu.Lock()
	current := m.generation
	m.mu.Unlock()
	require.NotSame(t, old, current)
	m.disconnectGeneration(old)
	require.True(t, m.IsConnected(), "a stale failure cannot disconnect the replacement")
	m.Forward(&data.PacketBatch{Sequence: 2, Packets: []*data.CapturedPacket{{}}})
	require.Eventually(t, func() bool { return secondService.batches.Load() == 1 }, time.Second, time.Millisecond)
}

func TestUpstreamCancellationInterruptsStalledAttempt(t *testing.T) {
	service := &candidateService{hang: true}
	address, _ := startCandidate(t, service)
	cfg := fastFailover()
	cfg.AttemptTimeout = time.Hour
	m := NewManager(Config{Address: address, Failover: cfg, ProcessorID: "relay", ListenAddress: "localhost:55555"}, nil)
	require.NoError(t, m.Start())
	require.Eventually(t, func() bool { return service.registrations.Load() > 0 }, time.Second, time.Millisecond)
	done := make(chan struct{})
	go func() { m.Disconnect(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("shutdown did not cancel registration")
	}
}

func (s *candidateService) StreamRelayPackets(stream data.RelayDataService_StreamRelayPacketsServer) error {
	open, err := stream.Recv()
	if err != nil {
		return err
	}
	if open.GetProtocolVersion() != 1 || open.GetRelayId() != "relay" || open.GetBatch() != nil {
		return status.Error(codes.InvalidArgument, "invalid open")
	}
	if s.relayReject {
		return status.Error(codes.PermissionDenied, "relay delegation rejected")
	}
	if s.relayHang {
		<-stream.Context().Done()
		return stream.Context().Err()
	}
	if err := stream.Send(&data.StreamControl{}); err != nil {
		return err
	}
	for {
		message, err := stream.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if message.GetRelayId() != open.GetRelayId() || message.GetProtocolVersion() != 1 || message.GetBatch() == nil {
			return status.Error(codes.InvalidArgument, "invalid envelope")
		}
		s.relayBatches <- message.Batch
		if err := stream.Send(&data.StreamControl{AckSequence: message.Batch.Sequence}); err != nil {
			return err
		}
	}
}

func TestUpstreamRelayOpenRejectedDoesNotFallbackToDirectPackets(t *testing.T) {
	rejected := &candidateService{relayVersion: 1, relayReject: true}
	first, _ := startCandidate(t, rejected)
	accepted := &candidateService{relayVersion: 1, relayBatches: make(chan *data.PacketBatch, 1)}
	second, _ := startCandidate(t, accepted)
	m := NewManager(Config{Endpoints: []failover.Endpoint{{Address: first}, {Address: second}}, Failover: fastFailover(), ProcessorID: "relay", ListenAddress: "localhost:55555"}, nil)
	require.NoError(t, m.Start())
	defer m.Disconnect()
	require.Eventually(t, func() bool { return m.ActiveAddress() == second }, 2*time.Second, time.Millisecond)
	require.Zero(t, rejected.batches.Load(), "v1 rejection must never invoke legacy StreamPackets")
	batch := &data.PacketBatch{HunterId: "edge", ProducerSessionId: "capture-session", CaptureEpoch: "epoch-12", Sequence: 37, Packets: []*data.CapturedPacket{{}}}
	m.Forward(batch)
	select {
	case received := <-accepted.relayBatches:
		require.True(t, proto.Equal(batch, received), "relay envelope preserves original identity and capture data")
	case <-time.After(time.Second):
		t.Fatal("relay batch was not delivered")
	}
}

func TestUpstreamBoundsRelayOpenAcknowledgment(t *testing.T) {
	stalled := &candidateService{relayVersion: 1, relayHang: true}
	first, _ := startCandidate(t, stalled)
	accepted := &candidateService{relayVersion: 1, relayBatches: make(chan *data.PacketBatch, 1)}
	second, _ := startCandidate(t, accepted)
	m := NewManager(Config{Endpoints: []failover.Endpoint{{Address: first}, {Address: second}}, Failover: fastFailover(), ProcessorID: "relay", ListenAddress: "localhost:55555"}, nil)
	require.NoError(t, m.Start())
	defer m.Disconnect()
	require.Eventually(t, func() bool { return m.ActiveAddress() == second }, 2*time.Second, time.Millisecond)
}

func TestUpstreamFailedPacketFallbackDoesNotChangeCommittedEventMode(t *testing.T) {
	rejected := &candidateService{relayVersion: 1, relayReject: true}
	first, _ := startCandidate(t, rejected)
	accepted := &candidateService{registration: &management.ProcessorRegistrationResponse{Accepted: true, UpstreamProcessorId: "event-upstream", AcceptedForwardingMode: management.ForwardingMode_FORWARDING_MODE_EVENTS, AcceptedEventApiMajor: 1, AcceptedSemanticProfileRevision: 1, AcceptedEventKinds: []int32{1, 2, 3, 4, 5, 6, 7}}}
	second, _ := startCandidate(t, accepted)
	m := NewManager(Config{Endpoints: []failover.Endpoint{{Address: first}, {Address: second}}, Failover: fastFailover(), ProcessorID: "relay", ListenAddress: "localhost:55555", ForwardMode: "events", EventFallbackToPackets: true}, nil)
	require.NoError(t, m.Start())
	defer m.Disconnect()
	require.Equal(t, second, m.ActiveAddress())
	require.True(t, m.ForwardingEvents(), "failed candidate packet selection cannot commit fallback")
	require.Equal(t, "event-upstream", m.GetUpstreamProcessorID())
	require.True(t, m.IsConnected())
}
