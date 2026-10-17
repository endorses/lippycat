//go:build hunter || all

package connection

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/endorses/lippycat/api/gen/data"
	eventsv1 "github.com/endorses/lippycat/api/gen/events/v1"
	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/failover"
	"github.com/endorses/lippycat/internal/pkg/hunter/eventforwarding"
	"github.com/endorses/lippycat/internal/pkg/hunter/eventspool"
	"github.com/endorses/lippycat/internal/pkg/hunter/forwarding"
	"github.com/endorses/lippycat/internal/pkg/pipeline"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type candidateProcessor struct {
	management.UnimplementedManagementServiceServer
	data.UnimplementedDataServiceServer
	eventsv1.UnimplementedEventServiceServer
	registrations        atomic.Int32
	reject               atomic.Bool
	stallRegistration    bool
	registrationReleased chan struct{}
	failData             bool
	stallData            bool
	dataEntered          chan struct{}
	dataReleased         chan struct{}
	eventMode            bool
	eventProfile         eventsv1.IngressProfile
	opened               chan *eventsv1.EventIngressOpen
	batches              chan *eventsv1.ProtocolEventBatch
	probes               atomic.Int32
}

func (s *candidateProcessor) RegisterHunter(ctx context.Context, req *management.HunterRegistration) (*management.RegistrationResponse, error) {
	s.registrations.Add(1)
	if s.stallRegistration {
		<-ctx.Done()
		if s.registrationReleased != nil {
			close(s.registrationReleased)
		}
		return nil, ctx.Err()
	}
	if s.reject.Load() {
		return nil, status.Error(codes.Unavailable, "processor unavailable")
	}
	response := &management.RegistrationResponse{Accepted: true, AssignedId: req.HunterId}
	if s.eventMode {
		response.AcceptedForwardingMode = management.ForwardingMode_FORWARDING_MODE_EVENTS
		response.AcceptedEventApiMajor = 1
		response.AcceptedSemanticProfileRevision = 1
		response.AcceptedEventKinds = []int32{1, 2, 3, 4, 5, 6, 7}
	}
	return response, nil
}
func (s *candidateProcessor) StreamPackets(stream data.DataService_StreamPacketsServer) error {
	if s.failData {
		return status.Error(codes.Unimplemented, "no packet ingress")
	}
	for {
		batch, err := stream.Recv()
		if err != nil {
			return err
		}
		if s.stallData {
			if s.dataEntered != nil {
				s.dataEntered <- struct{}{}
			}
			<-stream.Context().Done()
			if s.dataReleased != nil {
				s.dataReleased <- struct{}{}
			}
			return stream.Context().Err()
		}
		if batch.Sequence == 0 && len(batch.Packets) == 0 && batch.TimestampNs > 0 {
			s.probes.Add(1)
		}
		if err := stream.Send(&data.StreamControl{AckSequence: batch.Sequence, FlowControl: data.FlowControl_FLOW_CONTINUE}); err != nil {
			return err
		}
	}
}
func (s *candidateProcessor) Heartbeat(stream management.ManagementService_HeartbeatServer) error {
	for {
		if _, err := stream.Recv(); err != nil {
			return err
		}
		if err := stream.Send(&management.ProcessorHeartbeat{}); err != nil {
			return err
		}
	}
}
func (s *candidateProcessor) StreamEvents(stream eventsv1.EventService_StreamEventsServer) error {
	first, err := stream.Recv()
	if err != nil {
		return err
	}
	if s.opened != nil {
		s.opened <- first.GetOpen()
	}
	profile := s.eventProfile
	if profile == eventsv1.IngressProfile_INGRESS_PROFILE_UNSPECIFIED {
		profile = eventsv1.IngressProfile_INGRESS_PROFILE_RELIABLE
	}
	if err := stream.Send(&eventsv1.EventIngressControl{Kind: eventsv1.EventIngressControlKind_EVENT_INGRESS_CONTROL_KIND_ACCEPTED, AcceptedProfile: profile}); err != nil {
		return err
	}
	for {
		message, err := stream.Recv()
		if err != nil {
			return err
		}
		if s.batches != nil {
			s.batches <- message.GetBatch()
		}
	}
}
func startCandidate(t *testing.T, service *candidateProcessor) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	server := grpc.NewServer()
	management.RegisterManagementServiceServer(server, service)
	data.RegisterDataServiceServer(server, service)
	eventsv1.RegisterEventServiceServer(server, service)
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	t.Cleanup(func() { server.Stop(); require.NoError(t, <-done) })
	return listener.Addr().String()
}

type liveForwardingFactory struct{ capture *mockCaptureManager }

func (f *liveForwardingFactory) CreateForwardingManager(ctx context.Context, stream data.DataService_StreamPacketsClient) *forwarding.Manager {
	manager := forwarding.New(forwarding.Config{BatchSize: 1, BatchTimeout: time.Second}, &teardownStats{}, f.capture, ctx, make(chan *pipeline.PacketBatch))
	manager.SetStream(stream)
	return manager
}
func startFailoverManager(t *testing.T, cfg Config, eventClient *eventforwarding.Client) *Manager {
	manager, _ := startFailoverManagerWithFilters(t, cfg, eventClient, &mockFilterManager{})
	return manager
}
func startFailoverManagerWithFilters(t *testing.T, cfg Config, eventClient *eventforwarding.Client, filters FilterManager) (*Manager, <-chan struct{}) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	buffer, err := capture.NewPacketBufferWithConfig(ctx, capture.PacketBufferConfig{RegularCapacity: 8, SIPCapacity: 8, OutputCapacity: 8})
	require.NoError(t, err)
	t.Cleanup(buffer.Close)
	provider := &mockCaptureManager{buffer: buffer}
	manager := New(cfg, &mockStatsCollector{}, filters, provider, &liveForwardingFactory{capture: provider}, nil)
	if eventClient != nil {
		manager.SetEventForwarder(eventClient)
	}
	var wg sync.WaitGroup
	manager.Start(ctx, &wg)
	stopped := make(chan struct{})
	go func() { wg.Wait(); close(stopped) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-stopped:
		case <-time.After(3 * time.Second):
			t.Error("connection generations did not exit")
		}
	})
	return manager, stopped
}
func failoverTestConfig(addresses ...string) Config {
	config := Config{HunterID: "handover-hunter", ForwardMode: "packets", Failover: failover.Config{AttemptTimeout: 100 * time.Millisecond, ReconnectAttempts: 1, RetryInitial: 10 * time.Millisecond, RetryMax: 20 * time.Millisecond}}
	for _, address := range addresses {
		config.Processors = append(config.Processors, failover.Endpoint{Address: address})
	}
	return config
}
func awaitActive(t *testing.T, manager *Manager, address string) {
	t.Helper()
	require.Eventually(t, func() bool { return manager.Status().ActiveEndpoint == address }, 3*time.Second, time.Millisecond)
}
func TestFailoverSkipsRefusedStalledAndBrokenIngressCandidates(t *testing.T) {
	refused, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	refusedAddress := refused.Addr().String()
	require.NoError(t, refused.Close())
	stalled := &candidateProcessor{stallRegistration: true, registrationReleased: make(chan struct{})}
	stalledAddress := startCandidate(t, stalled)
	broken := &candidateProcessor{failData: true}
	brokenAddress := startCandidate(t, broken)
	healthy := &candidateProcessor{}
	healthyAddress := startCandidate(t, healthy)
	manager := startFailoverManager(t, failoverTestConfig(refusedAddress, stalledAddress, brokenAddress, healthyAddress), nil)
	awaitActive(t, manager, healthyAddress)
	require.Equal(t, int32(1), stalled.registrations.Load())
	require.Equal(t, int32(1), broken.registrations.Load())
	require.Equal(t, int32(1), healthy.probes.Load())
	select {
	case <-stalled.registrationReleased:
	case <-time.After(time.Second):
		t.Fatal("stalled registration did not inherit the setup deadline")
	}
	snapshot := manager.Status()
	snapshot.Candidates[0].Address = "modified"
	require.Equal(t, refusedAddress, manager.Status().Candidates[0].Address)
}
func TestFailoverRetainsHealthyStreamPastAttemptBudgetAndDoesNotFailBack(t *testing.T) {
	primary, backup := &candidateProcessor{}, &candidateProcessor{}
	primaryAddress, backupAddress := startCandidate(t, primary), startCandidate(t, backup)
	cfg := failoverTestConfig(primaryAddress, backupAddress)
	opened := make(chan struct{}, 2)
	cfg.OpenPacketStream = func(lifetimeCtx, setupCtx context.Context, conn grpc.ClientConnInterface) (data.DataService_StreamPacketsClient, error) {
		if _, ok := setupCtx.Deadline(); !ok {
			return nil, errors.New("missing setup deadline")
		}
		if _, ok := lifetimeCtx.Deadline(); ok {
			return nil, errors.New("setup deadline leaked into stream lifetime")
		}
		opened <- struct{}{}
		return data.NewDataServiceClient(conn).StreamPackets(lifetimeCtx)
	}
	manager := startFailoverManager(t, cfg, nil)
	awaitActive(t, manager, primaryAddress)
	time.Sleep(2 * cfg.Failover.AttemptTimeout)
	require.Equal(t, primaryAddress, manager.Status().ActiveEndpoint, "setup deadline leaked into healthy stream")
	require.Equal(t, int32(1), primary.registrations.Load())
	primary.reject.Store(true)
	manager.MarkDisconnected()
	awaitActive(t, manager, backupAddress)
	require.Equal(t, int32(2), primary.registrations.Load(), "configured current-peer reconnect opportunity")
	primary.reject.Store(false)
	time.Sleep(2 * cfg.Failover.AttemptTimeout)
	require.Equal(t, backupAddress, manager.Status().ActiveEndpoint)
	require.Equal(t, int32(2), primary.registrations.Load(), "healthy backup must stay selected")
	require.Equal(t, uint64(1), manager.Status().Failovers)
	require.Len(t, opened, 2, "custom packet transport hook must open primary and backup")
}
func testEventClient(t *testing.T) *eventforwarding.Client {
	t.Helper()
	spool, err := eventspool.Open(eventspool.Config{Directory: t.TempDir(), MaxBytes: 1 << 20})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, spool.Close()) })
	client, err := eventforwarding.New(eventforwarding.Config{SourceNodeID: "handover-hunter", ProducerSessionID: "capture-session", EventKinds: []eventsv1.EventKind{1, 2, 3, 4, 5, 6, 7}, SemanticProfileRevision: 1}, spool)
	require.NoError(t, err)
	return client
}
func TestFailedPacketFallbackDoesNotPublishModeOrChangeProducer(t *testing.T) {
	fallback := &candidateProcessor{failData: true}
	backup := &candidateProcessor{eventMode: true, opened: make(chan *eventsv1.EventIngressOpen, 1)}
	fallbackAddress, backupAddress := startCandidate(t, fallback), startCandidate(t, backup)
	cfg := failoverTestConfig(fallbackAddress, backupAddress)
	cfg.ForwardMode = "events"
	cfg.EventFallbackToPackets = true
	manager := startFailoverManager(t, cfg, testEventClient(t))
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	mode, err := manager.WaitAcceptedMode(ctx)
	require.NoError(t, err)
	require.Equal(t, management.ForwardingMode_FORWARDING_MODE_EVENTS, mode)
	awaitActive(t, manager, backupAddress)
	select {
	case open := <-backup.opened:
		require.Equal(t, "capture-session", open.ProducerSessionId)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
}
func TestEventWrongDeliveryProfileCannotPublishReadiness(t *testing.T) {
	bad := &candidateProcessor{eventMode: true, eventProfile: eventsv1.IngressProfile_INGRESS_PROFILE_MEMORY_ONLY}
	good := &candidateProcessor{eventMode: true}
	badAddress, goodAddress := startCandidate(t, bad), startCandidate(t, good)
	cfg := failoverTestConfig(badAddress, goodAddress)
	cfg.ForwardMode = "events"
	manager := startFailoverManager(t, cfg, testEventClient(t))
	awaitActive(t, manager, goodAddress)
	require.Equal(t, int32(1), bad.registrations.Load())
	require.Equal(t, int32(1), good.registrations.Load())
}

func TestStalledPacketReadinessCancelsGenerationBeforeAlternative(t *testing.T) {
	stalled := &candidateProcessor{stallData: true, dataEntered: make(chan struct{}, 1), dataReleased: make(chan struct{}, 1)}
	healthy := &candidateProcessor{}
	stalledAddress, healthyAddress := startCandidate(t, stalled), startCandidate(t, healthy)
	manager := startFailoverManager(t, failoverTestConfig(stalledAddress, healthyAddress), nil)
	awaitActive(t, manager, healthyAddress)
	select {
	case <-stalled.dataEntered:
	case <-time.After(time.Second):
		t.Fatal("packet probe did not reach stalled ingress")
	}
	select {
	case <-stalled.dataReleased:
	case <-time.After(time.Second):
		t.Fatal("stalled packet stream outlived its failed generation")
	}
	require.Equal(t, int32(1), stalled.registrations.Load())
}

func TestAllCandidatesDownBackoffIsCancellable(t *testing.T) {
	primary, backup := &candidateProcessor{}, &candidateProcessor{}
	primary.reject.Store(true)
	backup.reject.Store(true)
	primaryAddress, backupAddress := startCandidate(t, primary), startCandidate(t, backup)
	cfg := failoverTestConfig(primaryAddress, backupAddress)
	cfg.Failover.RetryInitial = time.Hour
	cfg.Failover.RetryMax = time.Hour
	manager, stopped := startFailoverManagerWithFilters(t, cfg, nil, &mockFilterManager{})
	require.Eventually(t, func() bool { return manager.Status().State == "waiting" }, time.Second, time.Millisecond)
	require.Equal(t, int32(1), primary.registrations.Load())
	require.Equal(t, int32(1), backup.registrations.Load())
	manager.Stop()
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("stop did not interrupt endpoint cooldown")
	}
	require.Nil(t, manager.GetDataClient())
	require.Nil(t, manager.GetMgmtClient())
	require.Nil(t, manager.GetStream())
	require.Nil(t, manager.GetForwardingManager())
}

type initializingFilterManager struct {
	mockFilterManager
	initialize func(context.Context, grpc.ClientConnInterface) error
	pending    func() error
}

func (f *initializingFilterManager) InitializePolicy(ctx context.Context, conn grpc.ClientConnInterface) error {
	return f.initialize(ctx, conn)
}
func (f *initializingFilterManager) ApplyPendingInitialE() error {
	if f.pending != nil {
		return f.pending()
	}
	return nil
}

func TestPolicyInitializationRejectsCandidateBeforeProducerModePublication(t *testing.T) {
	rejected := &candidateProcessor{}
	accepted := &candidateProcessor{eventMode: true}
	rejectedAddress, acceptedAddress := startCandidate(t, rejected), startCandidate(t, accepted)
	cfg := failoverTestConfig(rejectedAddress, acceptedAddress)
	cfg.ForwardMode = "events"
	cfg.EventFallbackToPackets = true
	calls := make(chan string, 2)
	filters := &initializingFilterManager{initialize: func(ctx context.Context, conn grpc.ClientConnInterface) error {
		if _, ok := ctx.Deadline(); !ok {
			return errors.New("policy setup has no attempt deadline")
		}
		target := conn.(*grpc.ClientConn).Target()
		calls <- target
		if target == rejectedAddress {
			return errors.New("untrusted candidate policy")
		}
		return nil
	}}
	manager, _ := startFailoverManagerWithFilters(t, cfg, testEventClient(t), filters)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	mode, err := manager.WaitAcceptedMode(ctx)
	require.NoError(t, err)
	require.Equal(t, management.ForwardingMode_FORWARDING_MODE_EVENTS, mode)
	awaitActive(t, manager, acceptedAddress)
	require.Equal(t, rejectedAddress, <-calls)
	require.Equal(t, acceptedAddress, <-calls)
}

func TestTransportGettersRemainSafeDuringGenerationReplacement(t *testing.T) {
	primary, backup := &candidateProcessor{}, &candidateProcessor{}
	primaryAddress, backupAddress := startCandidate(t, primary), startCandidate(t, backup)
	manager, stopped := startFailoverManagerWithFilters(t, failoverTestConfig(primaryAddress, backupAddress), nil, &mockFilterManager{})
	readersDone := make(chan struct{})
	go func() {
		defer close(readersDone)
		for {
			select {
			case <-stopped:
				return
			default:
			}
			_ = manager.GetDataClient()
			_ = manager.GetMgmtClient()
			_ = manager.GetStream()
			_ = manager.GetForwardingManager()
			_ = manager.Status()
		}
	}()
	awaitActive(t, manager, primaryAddress)
	primary.reject.Store(true)
	manager.MarkDisconnected()
	awaitActive(t, manager, backupAddress)
	manager.Stop()
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("generation did not exit")
	}
	select {
	case <-readersDone:
	case <-time.After(time.Second):
		t.Fatal("snapshot reader did not exit")
	}
}

func TestFailedPendingPolicyDoesNotPublishReadiness(t *testing.T) {
	bad, good := &candidateProcessor{}, &candidateProcessor{eventMode: true}
	badAddress, goodAddress := startCandidate(t, bad), startCandidate(t, good)
	cfg := failoverTestConfig(badAddress, goodAddress)
	cfg.ForwardMode = "events"
	cfg.EventFallbackToPackets = true
	var candidate string
	filters := &initializingFilterManager{initialize: func(_ context.Context, conn grpc.ClientConnInterface) error {
		candidate = conn.(*grpc.ClientConn).Target()
		return nil
	}}
	filters.pending = func() error {
		if candidate == badAddress {
			return errors.New("pending policy publication failed")
		}
		return nil
	}
	manager, _ := startFailoverManagerWithFilters(t, cfg, testEventClient(t), filters)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	mode, err := manager.WaitAcceptedMode(ctx)
	require.NoError(t, err)
	require.Equal(t, management.ForwardingMode_FORWARDING_MODE_EVENTS, mode)
	awaitActive(t, manager, goodAddress)
	require.Equal(t, int32(1), bad.registrations.Load(), "policy failure must advance to another candidate")
}
