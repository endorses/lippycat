//go:build all

package hunter

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	eventsv1 "github.com/endorses/lippycat/api/gen/events/v1"
	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/eventconfig"
	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/endorses/lippycat/internal/pkg/events/protoadapter"
	"github.com/endorses/lippycat/internal/pkg/failover"
	"github.com/endorses/lippycat/internal/pkg/processor"
	"github.com/endorses/lippycat/internal/testutil/eventfixture"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

func startSSHHunter(t *testing.T, address, certificate, key string) (*Hunter, func()) {
	t.Helper()
	policy := eventconfig.Default()
	policy.Inventory.Enabled = false
	h, err := New(Config{HunterID: "ssh-edge", ProcessorAddr: address, ForwardMode: "events", EventAnalysis: &policy, EventDeliveryProfile: "memory_only", EventSpoolDir: t.TempDir(), BufferSize: 4096, BatchSize: 16, BatchTimeout: time.Millisecond,
		TLSEnabled: true, TLSCAFile: certificate, TLSCertFile: certificate, TLSKeyFile: key, NoFilterPolicy: "allow", Failover: failover.Config{AttemptTimeout: time.Second, RetryInitial: 10 * time.Millisecond, RetryMax: 20 * time.Millisecond}})
	require.NoError(t, err)
	require.NoError(t, h.captureManager.PrepareBuffer())
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- h.Start(ctx) }()
	stop := sync.OnceFunc(func() {
		cancel()
		select {
		case err := <-done:
			require.NoError(t, err)
		case <-time.After(10 * time.Second):
			t.Error("SSH hunter did not join")
		}
		require.NoError(t, h.Close())
	})
	t.Cleanup(stop)
	require.Eventually(t, func() bool { return h.statsCollector.ToProto(0).GetProcessorSelection().GetState() == "connected" }, 5*time.Second, time.Millisecond)
	return h, stop
}

func startSSHReceiver(t *testing.T, certificate, key, directory string) (*processor.Processor, func()) {
	t.Helper()
	p, err := processor.New(processor.Config{ProcessorID: "ssh-receiver", ListenAddr: "127.0.0.1:0", FilterFile: filepath.Join(t.TempDir(), "managed", "filters.yaml"), TLSEnabled: true, TLSClientAuth: true, TLSCAFile: certificate, TLSCertFile: certificate, TLSKeyFile: key, EventIngressProfile: "memory_only", EventQueueSize: 32, GracefulShutdownTimeout: 100 * time.Millisecond,
		LogConfig: &processor.StructuredLogConfig{Enabled: true, Directory: directory, Format: "json", Streams: []string{"ssh"}, QueueSize: 16}})
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- p.Start(ctx) }()
	stop := sync.OnceFunc(func() {
		cancel()
		select {
		case err := <-done:
			require.NoError(t, err)
		case <-time.After(10 * time.Second):
			t.Error("SSH processor did not join")
		}
	})
	t.Cleanup(stop)
	require.Eventually(t, func() bool { return p.ListenAddr() != "" }, 5*time.Second, time.Millisecond)
	return p, stop
}

func TestSSHActualHunterTransportSubscriptionAndLog(t *testing.T) {
	pair, certificate, key, roots := rawIntegrationCertificate(t)
	directory := t.TempDir()
	receiver, stopReceiver := startSSHReceiver(t, certificate, key, directory)
	conn, err := grpc.NewClient(receiver.ListenAddr(), grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{pair}, RootCAs: roots})))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, conn.Close()) })
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	// The same metadata is public, but the existing sensitive-field opt-in still
	// requires authorization rather than bypassing policy for a new event kind.
	denied, err := eventsv1.NewEventServiceClient(conn).SubscribeEvents(ctx, &eventsv1.EventSubscribeRequest{SubscriptionVersion: 1, EventKinds: []eventsv1.EventKind{eventsv1.EventKind_EVENT_KIND_SSH}, IncludeSensitiveFields: true})
	require.NoError(t, err)
	_, err = denied.Recv()
	require.Equal(t, codes.PermissionDenied, status.Code(err))
	subscription, err := eventsv1.NewEventServiceClient(conn).SubscribeEvents(ctx, &eventsv1.EventSubscribeRequest{SubscriptionVersion: 1, EventKinds: []eventsv1.EventKind{eventsv1.EventKind_EVENT_KIND_SSH}})
	require.NoError(t, err)
	control, err := subscription.Recv()
	require.NoError(t, err)
	require.Contains(t, control.GetControl().SupportedEventKinds, eventsv1.EventKind_EVENT_KIND_SSH)
	h, stopHunter := startSSHHunter(t, receiver.ListenAddr(), certificate, key)
	packets, err := eventfixture.SSHMessages()
	require.NoError(t, err)
	for _, packet := range packets {
		require.True(t, h.captureManager.GetPacketBuffer().Send(packet))
	}
	var observed []events.SSHEvent
	for len(observed) < 4 {
		msg, err := subscription.Recv()
		require.NoError(t, err)
		for _, wire := range msg.GetBatch().Events {
			decoded, omitted, err := protoadapter.FromProto(wire)
			require.NoError(t, err)
			require.Nil(t, omitted)
			e := decoded.(events.SSHEvent)
			require.True(t, events.HasValidDeliveryIdentity(e.Envelope()))
			require.Equal(t, "ssh-edge", e.Envelope().NodeID)
			observed = append(observed, e)
		}
	}
	roles := map[events.SSHRole]bool{}
	ids := map[string]bool{}
	var uid string
	for _, e := range observed {
		require.False(t, ids[e.Envelope().EventID])
		ids[e.Envelope().EventID] = true
		if uid == "" {
			uid = e.Envelope().UID
		}
		require.Equal(t, uid, e.Envelope().UID)
		if e.Status == events.SSHStatusComplete {
			require.NotEmpty(t, e.HASSH)
			require.Equal(t, "1.0", e.HASSHVersion)
			roles[e.Role] = true
		}
	}
	require.True(t, roles[events.SSHRoleClient])
	require.True(t, roles[events.SSHRoleServer])
	require.Zero(t, receiver.GetStats().TotalPacketsReceived, "event ingress must not reparse transported SSH")
	cancel()
	stopHunter()
	stopReceiver()
	raw, err := os.ReadFile(filepath.Join(directory, "ssh.log"))
	require.NoError(t, err)
	rows := strings.Split(strings.TrimSpace(string(raw)), "\n")
	require.Len(t, rows, len(observed))
	for _, row := range rows {
		var record map[string]any
		require.NoError(t, json.Unmarshal([]byte(row), &record))
		require.True(t, ids[record["event_id"].(string)])
		require.Equal(t, "ssh-edge", record["node_id"])
		if record["status"] == "complete" {
			require.NotEmpty(t, record["hassh"])
			require.NotEmpty(t, record["kex_algorithms"])
		} else {
			require.Nil(t, record["hassh"])
			require.Nil(t, record["kex_algorithms"])
		}
	}
}

func TestSSHConfiguredLogRequiresKindFromLegacySource(t *testing.T) {
	pair, certificate, key, roots := rawIntegrationCertificate(t)
	receiver, _ := startSSHReceiver(t, certificate, key, t.TempDir())
	conn, err := grpc.NewClient(receiver.ListenAddr(), grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{pair}, RootCAs: roots})))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, conn.Close()) })
	var old []int32
	for _, kind := range protoadapter.SupportedKindIDs(false) {
		if kind != 13 {
			old = append(old, kind)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, fallback := range []bool{false, true} {
		response, err := management.NewManagementServiceClient(conn).RegisterHunter(ctx, &management.HunterRegistration{HunterId: "legacy-ssh-source", EventForwarding: &management.EventForwardingCapabilities{RequestedMode: management.ForwardingMode_FORWARDING_MODE_EVENTS, EventApiMajors: []uint32{1}, SemanticProfileRevision: 1, StatefulAnalysisFeatures: []string{"tcp_reassembly", "connection_tracking", "file_metadata"}, EventKinds: old, AllowPacketFallback: fallback}})
		if fallback {
			require.NoError(t, err)
			require.Equal(t, management.ForwardingMode_FORWARDING_MODE_PACKETS, response.AcceptedForwardingMode)
			require.Contains(t, response.ForwardingNotice, "SSH")
		} else {
			require.Equal(t, codes.FailedPrecondition, status.Code(err))
			require.Contains(t, err.Error(), "SSH")
		}
	}
}

// A legacy processor negotiates the older kind set, then accepts normal batches
// and explicit omission carriers. The actual current hunter owns production,
// dispatch, spool, network delivery, acknowledgement and loss counters.
type sshLegacyPeer struct {
	management.UnimplementedManagementServiceServer
	eventsv1.UnimplementedEventServiceServer
	losses chan *eventsv1.EventLoss
}

func (p *sshLegacyPeer) RegisterHunter(_ context.Context, req *management.HunterRegistration) (*management.RegistrationResponse, error) {
	var accepted []int32
	for _, kind := range protoadapter.SupportedKindIDs(false) {
		if kind != 13 {
			accepted = append(accepted, kind)
		}
	}
	return &management.RegistrationResponse{Accepted: true, AssignedId: req.HunterId, AcceptedForwardingMode: management.ForwardingMode_FORWARDING_MODE_EVENTS, AcceptedEventApiMajor: 1, AcceptedSemanticProfileRevision: 1, AcceptedEventKinds: accepted}, nil
}
func (p *sshLegacyPeer) Heartbeat(stream management.ManagementService_HeartbeatServer) error {
	for {
		_, err := stream.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if err = stream.Send(&management.ProcessorHeartbeat{ProcessorId: "legacy-ssh", TimestampNs: time.Now().UnixNano()}); err != nil {
			return err
		}
	}
}
func (p *sshLegacyPeer) SubscribeFilters(_ *management.FilterRequest, stream management.ManagementService_SubscribeFiltersServer) error {
	<-stream.Context().Done()
	return nil
}

func (p *sshLegacyPeer) StreamEvents(stream eventsv1.EventService_StreamEventsServer) error {
	first, err := stream.Recv()
	if err != nil {
		return err
	}
	if err = stream.Send(&eventsv1.EventIngressControl{Kind: eventsv1.EventIngressControlKind_EVENT_INGRESS_CONTROL_KIND_ACCEPTED, AcceptedProfile: first.GetOpen().Profile}); err != nil {
		return err
	}
	for {
		msg, err := stream.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		batch := msg.GetBatch()
		if batch == nil {
			continue
		}
		for _, event := range batch.Events {
			if event.GetSsh() != nil {
				return status.Error(codes.InvalidArgument, "legacy peer received unsupported SSH payload")
			}
		}
		for _, loss := range batch.GetStats().GetLosses() {
			if loss.Kind == eventsv1.LossKind_LOSS_KIND_UNSUPPORTED_EVENT {
				select {
				case p.losses <- proto.Clone(loss).(*eventsv1.EventLoss):
				case <-stream.Context().Done():
					return stream.Context().Err()
				}
			}
		}
		if err = stream.Send(&eventsv1.EventIngressControl{Kind: eventsv1.EventIngressControlKind_EVENT_INGRESS_CONTROL_KIND_ACK, CumulativeAckSequence: batch.BatchSequence}); err != nil {
			return err
		}
	}
}
func TestSSHActualHunterReportsOptionalUnsupportedKindLoss(t *testing.T) {
	pair, certificate, key, roots := rawIntegrationCertificate(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	peer := &sshLegacyPeer{losses: make(chan *eventsv1.EventLoss, 16)}
	server := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{pair}, ClientCAs: roots, ClientAuth: tls.RequireAndVerifyClientCert})))
	management.RegisterManagementServiceServer(server, peer)
	eventsv1.RegisterEventServiceServer(server, peer)
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	t.Cleanup(func() { server.Stop(); require.NoError(t, <-done) })
	h, stop := startSSHHunter(t, listener.Addr().String(), certificate, key)
	packets, err := eventfixture.SSHMessages()
	require.NoError(t, err)
	for _, packet := range packets {
		require.True(t, h.captureManager.GetPacketBuffer().Send(packet))
	}
	// Unsupported observations remain explicit durable loss coverage until a
	// supported event or Flush carries them. A following DNS observation is a
	// production barrier which sends the pending carrier without shutting down.
	dns := dnsNoticeHunterPacket(t)
	dns.Packet.Metadata().Timestamp = packets[len(packets)-1].Packet.Metadata().Timestamp.Add(time.Second)
	require.True(t, h.captureManager.GetPacketBuffer().Send(dns))
	var count uint64
	for count < 4 {
		select {
		case loss := <-peer.losses:
			require.Equal(t, "ssh-edge", loss.SourceNodeId)
			require.NotEmpty(t, loss.EventSequenceRanges)
			count += loss.Count
		case <-time.After(10 * time.Second):
			t.Fatalf("legacy peer received %d of 4 SSH compatibility omissions; stats=%v", count, h.statsCollector.ToProto(0))
		}
	}
	require.GreaterOrEqual(t, h.statsCollector.ToProto(0).UnsupportedKindLosses, uint64(4))
	stop()
}
