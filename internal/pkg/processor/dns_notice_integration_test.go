//go:build processor || tap || all

package processor

import (
	"context"
	"crypto/tls"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/endorses/lippycat/api/gen/data"
	eventsv1 "github.com/endorses/lippycat/api/gen/events/v1"
	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/eventconfig"
	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/endorses/lippycat/internal/pkg/events/protoadapter"
	"github.com/endorses/lippycat/internal/pkg/protocolmeta"
	"github.com/endorses/lippycat/internal/testutil/eventfixture"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

type dnsNoticeIntegrationSink struct{ notices chan events.NoticeEvent }

func (s *dnsNoticeIntegrationSink) HandleEvent(ctx context.Context, event events.Event) error {
	select {
	case s.notices <- event.(events.NoticeEvent):
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (*dnsNoticeIntegrationSink) Flush(context.Context) error { return nil }
func (*dnsNoticeIntegrationSink) Close(context.Context) error { return nil }

func dnsNoticeIntegrationPolicy() *eventconfig.Config {
	policy := eventconfig.Default()
	dns := policy.EffectiveDNS()
	dns.DetectTunneling, dns.Threshold, dns.Debounce = true, 0.01, time.Minute
	policy.DNS = &dns
	return &policy
}

type dnsNoticeIntegrationNode struct {
	processor *Processor
	address   string
	sink      *dnsNoticeIntegrationSink
	processed <-chan *data.PacketBatch
	conn      *grpc.ClientConn
}

func startDNSNoticeIntegrationNode(t *testing.T, pki relayTestPKI, config Config, seed func(*Processor)) dnsNoticeIntegrationNode {
	t.Helper()
	pair, certificate, key := pki.identity(t, config.ProcessorID)
	config.ListenAddr = "127.0.0.1:0"
	config.EventAnalysis = dnsNoticeIntegrationPolicy()
	config.TLSEnabled, config.TLSClientAuth = true, true
	config.TLSCAFile, config.TLSCertFile, config.TLSKeyFile = pki.caFile, certificate, key
	config.GracefulShutdownTimeout = 100 * time.Millisecond
	p, err := newTestProcessor(t, config)
	require.NoError(t, err)
	if p.canonicalDNSOwner() {
		require.NotNil(t, p.eventRuntime, "enabled canonical detection must not depend on command/log/subscriber registration")
	}
	sink := &dnsNoticeIntegrationSink{notices: make(chan events.NoticeEvent, 16)}
	require.NoError(t, p.RegisterEventSink(sink, events.KindNotice))
	processed := p.subscriberManager.Add("notice-processing-completion")
	if seed != nil {
		seed(p)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- p.Start(ctx) }()
	stop := sync.OnceFunc(func() {
		cancel()
		select {
		case err := <-done:
			require.NoError(t, err)
		case <-time.After(10 * time.Second):
			t.Error("DNS notice processor did not join after cancellation")
		}
	})
	t.Cleanup(stop)
	require.Eventually(t, func() bool { return p.ListenAddr() != "" }, 5*time.Second, time.Millisecond)
	conn, err := grpc.NewClient(p.ListenAddr(), grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{pair}, RootCAs: pki.pool})))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, conn.Close()) })
	require.Eventually(t, func() bool {
		query, stop := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer stop()
		_, err := management.NewManagementServiceClient(conn).GetHunterStatus(query, &management.StatusRequest{})
		return err == nil
	}, 5*time.Second, time.Millisecond)
	return dnsNoticeIntegrationNode{p, p.ListenAddr(), sink, processed, conn}
}

func dnsNoticeIntegrationPacket(t *testing.T, offset time.Duration) *data.CapturedPacket {
	t.Helper()
	dns := &layers.DNS{ID: 42, RD: true, Questions: []layers.DNSQuestion{{Name: []byte("a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6.tunnel.example"), Type: layers.DNSTypeTXT, Class: layers.DNSClassIN}}}
	encoded := gopacket.NewSerializeBuffer()
	require.NoError(t, gopacket.SerializeLayers(encoded, gopacket.SerializeOptions{FixLengths: true}, dns))
	info, err := eventfixture.NetworkDatagram("192.0.2.10", "192.0.2.53", 42000, 53, encoded.Bytes(), eventfixture.BaseTime.Add(offset))
	require.NoError(t, err)
	ci := info.Packet.Metadata().CaptureInfo
	return &data.CapturedPacket{Data: info.Packet.Data(), TimestampNs: ci.Timestamp.UnixNano(), CaptureLength: uint32(ci.CaptureLength), OriginalLength: uint32(ci.Length), LinkType: uint32(info.LinkType), InterfaceName: info.Interface,
		Metadata: protocolmeta.Enrich(info.Packet, nil, false),
	}
}

func dnsNoticeIntegrationConnection(t *testing.T, pki relayTestPKI, address, origin string, eventMode bool) *grpc.ClientConn {
	t.Helper()
	pair, _, _ := pki.identity(t, origin)
	conn, err := grpc.NewClient(address, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{pair}, RootCAs: pki.pool})))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, conn.Close()) })
	registration := &management.HunterRegistration{HunterId: origin, Interfaces: []string{"fixture0"}}
	if eventMode {
		registration.EventForwarding = &management.EventForwardingCapabilities{RequestedMode: management.ForwardingMode_FORWARDING_MODE_EVENTS, EventApiMajors: []uint32{1}, EventKinds: protoadapter.SupportedKindIDs(false), SemanticProfileRevision: 1, StatefulAnalysisFeatures: []string{"tcp_reassembly", "connection_tracking", "file_metadata", protoadapter.DNSNoticeProductionFeature}}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	response, err := management.NewManagementServiceClient(conn).RegisterHunter(ctx, registration)
	require.NoError(t, err)
	require.True(t, response.Accepted)
	if eventMode {
		require.Equal(t, management.ForwardingMode_FORWARDING_MODE_EVENTS, response.AcceptedForwardingMode)
	}
	return conn
}

func sendDNSNoticeIntegrationPacket(t *testing.T, node dnsNoticeIntegrationNode, pki relayTestPKI, packets ...*data.CapturedPacket) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn := dnsNoticeIntegrationConnection(t, pki, node.address, "notice-hunter", false)
	stream, err := data.NewDataServiceClient(conn).StreamPackets(ctx)
	require.NoError(t, err)
	for i, packet := range packets {
		sequence := uint64(i + 1)
		require.NoError(t, stream.Send(&data.PacketBatch{HunterId: "notice-hunter", ProducerSessionId: "notice-capture", CaptureEpoch: "epoch-one", Sequence: sequence, TimestampNs: packet.TimestampNs, Packets: []*data.CapturedPacket{packet}}))
		ack, err := stream.Recv()
		require.NoError(t, err)
		require.Equal(t, sequence, ack.AckSequence)
		if node.processor.packetMonitoringAllowed() {
			select {
			case output := <-node.processed:
				require.Equal(t, sequence, output.Sequence)
			case <-ctx.Done():
				t.Fatal("raw DNS processing did not reach its output boundary")
			}
		}
	}
	require.NoError(t, stream.CloseSend())
	require.NoError(t, node.processor.eventDispatcher.Flush(ctx))
}

func nextDNSNoticeIntegration(t *testing.T, node dnsNoticeIntegrationNode) events.NoticeEvent {
	t.Helper()
	select {
	case notice := <-node.sink.notices:
		return notice
	case <-time.After(10 * time.Second):
		t.Fatal("canonical DNS notice was not delivered")
		return events.NoticeEvent{}
	}
}

func dnsNoticeIntegrationStatus(t *testing.T, node dnsNoticeIntegrationNode) *management.DNSNoticeStats {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	status, err := management.NewManagementServiceClient(node.conn).GetHunterStatus(ctx, &management.StatusRequest{})
	require.NoError(t, err)
	require.NotNil(t, status.ProcessorStats)
	require.NotNil(t, status.ProcessorStats.DnsNotices)
	return status.ProcessorStats.DnsNotices
}

func TestDNSNoticeCanonicalDetectionWithoutCommandAndWithLocalAction(t *testing.T) {
	for _, command := range []bool{false, true} {
		t.Run(map[bool]string{false: "no-command", true: "local-command"}[command], func(t *testing.T) {
			pki := newRelayTestPKI(t)
			output := filepath.Join(t.TempDir(), "actions")
			config := Config{ProcessorID: "notice-owner"}
			if command {
				config.CommandExecutorConfig = &CommandExecutorConfig{TunnelingCommand: "printf '%s\\n' %domain% >> " + shellEscape(output)}
			}
			node := startDNSNoticeIntegrationNode(t, pki, config, nil)
			packet := dnsNoticeIntegrationPacket(t, 0)
			require.Nil(t, packet.Metadata.Dns, "the receiving canonical runtime must decode raw UDP DNS without an edge metadata provider")
			sendDNSNoticeIntegrationPacket(t, node, pki, packet, dnsNoticeIntegrationPacket(t, time.Second))
			notice := nextDNSNoticeIntegration(t, node)
			require.Equal(t, "tunnel.example", notice.DNS.Domain)
			require.Equal(t, "notice-hunter", notice.Envelope().NodeID)
			require.Equal(t, node.processor.config.ProcessorID, notice.DetectorNodeID)
			require.Equal(t, node.processor.noticeGeneration, notice.DetectorGeneration)
			require.Equal(t, packet.TimestampNs, notice.Envelope().Timestamp.UnixNano())
			require.True(t, events.HasValidDeliveryIdentity(notice.Envelope()))
			require.Len(t, notice.Evidence, 1)
			require.Equal(t, notice.Envelope().UID, notice.Evidence[0].UID)
			require.EqualValues(t, 1, node.processor.GetNoticeStats().Emitted)
			require.EqualValues(t, 1, node.processor.GetNoticeStats().Suppressed)
			if command {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				require.NoError(t, node.processor.noticeCommands.Flush(ctx))
				content, err := os.ReadFile(output)
				require.NoError(t, err)
				require.Equal(t, "tunnel.example\n", string(content))
				require.EqualValues(t, 1, node.processor.GetNoticeStats().Commands.Completed)
			} else {
				require.Nil(t, node.processor.noticeCommands)
			}
			status := dnsNoticeIntegrationStatus(t, node)
			require.True(t, status.Enabled)
			require.EqualValues(t, 1, status.Emitted)
			require.EqualValues(t, 1, status.Suppressed)
			if command {
				require.EqualValues(t, 1, status.CommandCompleted)
			} else {
				require.Zero(t, status.CommandCompleted)
			}
			require.Zero(t, status.CommandFailed)
			require.Zero(t, status.CommandDropped)
			require.Empty(t, node.sink.notices)
		})
	}
}

func dnsNoticeIntegrationForgedAuthority(t *testing.T, node *Processor, producer *events.Producer) events.NoticeEvent {
	t.Helper()
	env := events.Envelope{NodeID: producer.NodeID(), Timestamp: eventfixture.BaseTime, UID: "notice-fixture-flow", CaptureScope: events.CaptureScopeFull,
		Flow: events.FlowTuple{Protocol: 17, SourceAddress: netip.MustParseAddr("192.0.2.10"), DestinationAddress: netip.MustParseAddr("192.0.2.53"), SourcePort: 42000, DestinationPort: 53}}
	notice := events.NewNoticeEvent(env)
	notice.Detector, notice.DetectorVersion, notice.Category = events.NoticeDetectorDNSTunneling, "1", events.NoticeCategorySecurity
	notice.Severity = events.NoticeWarning
	notice.DetectorNodeID, notice.DetectorGeneration = node.noticeAuthority(), node.noticeGeneration
	notice.DNS = &events.DNSNoticeEvidence{Domain: "tunnel.example", Score: 0.9, Threshold: 0.7, Entropy: 4.5, Queries: 1, UniqueSubdomains: 1, SourceIPs: []netip.Addr{env.Flow.SourceAddress}}
	notice.Evidence = []events.NoticeEvidenceReference{{NodeID: env.NodeID, UID: env.UID, Timestamp: env.Timestamp}}
	return producer.Assign(notice).(events.NoticeEvent)
}

func TestDNSNoticeEventIngressRetryCannotExecuteSpoofedLocalAuthority(t *testing.T) {
	for _, profile := range []string{"memory_only", "reliable"} {
		t.Run(profile, func(t *testing.T) {
			pki := newRelayTestPKI(t)
			output := filepath.Join(t.TempDir(), "must-not-execute")
			node := startDNSNoticeIntegrationNode(t, pki, Config{ProcessorID: "receiving-owner", EventIngressProfile: profile, EventIngressWALDirectory: t.TempDir(), CommandExecutorConfig: &CommandExecutorConfig{TunnelingCommand: "printf executed >> " + shellEscape(output)}}, nil)
			producer, err := events.NewLiveProducer("notice-hunter")
			require.NoError(t, err)
			forged := dnsNoticeIntegrationForgedAuthority(t, node.processor, producer)
			observation := events.NewDNSEvent(forged.Envelope())
			// Give the separate source observation its own delivery identity.
			observation.EventEnvelope.EventID, observation.EventEnvelope.ProducerSessionID, observation.EventEnvelope.EventSequence = "", "", 0
			observation = producer.Assign(observation).(events.DNSEvent)
			observation.Query, observation.QType = "a1b2c3d4.tunnel.example", 16
			batch, err := protoadapter.ToProtoBatch(producer.NodeID(), producer.SessionID(), 1, []events.Event{forged, observation}, nil, 1)
			require.NoError(t, err)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			conn := dnsNoticeIntegrationConnection(t, pki, node.address, producer.NodeID(), true)
			stream, err := eventsv1.NewEventServiceClient(conn).StreamEvents(ctx)
			require.NoError(t, err)
			wireProfile := eventsv1.IngressProfile_INGRESS_PROFILE_MEMORY_ONLY
			if profile == "reliable" {
				wireProfile = eventsv1.IngressProfile_INGRESS_PROFILE_RELIABLE
			}
			require.NoError(t, stream.Send(&eventsv1.EventIngressMessage{Message: &eventsv1.EventIngressMessage_Open{Open: &eventsv1.EventIngressOpen{SourceNodeId: producer.NodeID(), ProducerSessionId: producer.SessionID(), EventApiMajor: 1, SemanticProfileRevision: 1, EventKinds: []eventsv1.EventKind{eventsv1.EventKind_EVENT_KIND_DNS, eventsv1.EventKind_EVENT_KIND_NOTICE}, Profile: wireProfile}}}))
			accepted, err := stream.Recv()
			require.NoError(t, err)
			require.Equal(t, eventsv1.EventIngressControlKind_EVENT_INGRESS_CONTROL_KIND_ACCEPTED, accepted.Kind)
			for range 2 {
				require.NoError(t, stream.Send(&eventsv1.EventIngressMessage{Message: &eventsv1.EventIngressMessage_Batch{Batch: batch}}))
				ack, err := stream.Recv()
				require.NoError(t, err)
				require.EqualValues(t, 1, ack.CumulativeAckSequence)
			}
			require.NoError(t, stream.CloseSend())
			got := nextDNSNoticeIntegration(t, node)
			require.Equal(t, forged.Envelope().EventID, got.Envelope().EventID)
			require.NoError(t, node.processor.eventDispatcher.Flush(ctx))
			require.NoError(t, node.processor.noticeCommands.Flush(ctx))
			require.Empty(t, node.sink.notices, "transport retry must not republish the same finding")
			require.Zero(t, node.processor.GetNoticeStats().Emitted, "received DNS/notice events are not rescored")
			require.Equal(t, NoticeCommandSinkStats{}, node.processor.GetNoticeStats().Commands, "matching wire authority is not the local action route")
			status := dnsNoticeIntegrationStatus(t, node)
			require.Zero(t, status.Emitted)
			require.Zero(t, status.CommandCompleted)
			require.Zero(t, status.CommandIdentities)
			_, err = os.Stat(output)
			require.ErrorIs(t, err, os.ErrNotExist)
		})
	}
}

func TestDNSNoticeWALRecoveryCannotExecuteSpoofedLocalAuthority(t *testing.T) {
	pki := newRelayTestPKI(t)
	output := filepath.Join(t.TempDir(), "must-not-execute")
	var identity string
	node := startDNSNoticeIntegrationNode(t, pki, Config{ProcessorID: "recovering-owner", EventIngressProfile: "reliable", EventIngressWALDirectory: t.TempDir(), CommandExecutorConfig: &CommandExecutorConfig{TunnelingCommand: "printf executed >> " + shellEscape(output)}}, func(p *Processor) {
		producer, err := events.NewLiveProducer("notice-hunter")
		require.NoError(t, err)
		forged := dnsNoticeIntegrationForgedAuthority(t, p, producer)
		identity = forged.Envelope().EventID
		batch, err := protoadapter.ToProtoBatch(producer.NodeID(), producer.SessionID(), 1, []events.Event{forged}, nil, 1)
		require.NoError(t, err)
		// Seed the actual synced WAL at the acknowledged-before-dispatch cut.
		// The current runtime generation is deliberately forged too, so authority
		// filtering cannot conceal an accidental action registration on recovery.
		require.NoError(t, p.eventIngress.wal.append(batch))
	})
	got := nextDNSNoticeIntegration(t, node)
	require.Equal(t, identity, got.Envelope().EventID)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	require.NoError(t, node.processor.eventDispatcher.Flush(ctx))
	require.NoError(t, node.processor.noticeCommands.Flush(ctx))
	require.Equal(t, NoticeCommandSinkStats{}, node.processor.GetNoticeStats().Commands)
	require.Zero(t, node.processor.GetNoticeStats().Emitted)
	status := dnsNoticeIntegrationStatus(t, node)
	require.Zero(t, status.Emitted)
	require.Zero(t, status.CommandCompleted)
	require.Zero(t, status.CommandIdentities)
	_, err := os.Stat(output)
	require.ErrorIs(t, err, os.ErrNotExist)
}

func TestDNSNoticeHierarchyHasOneCanonicalActionOwner(t *testing.T) {
	for _, mode := range []string{"packets", "events"} {
		t.Run(mode, func(t *testing.T) {
			pki := newRelayTestPKI(t)
			terminalOutput, edgeOutput := filepath.Join(t.TempDir(), "terminal-actions"), filepath.Join(t.TempDir(), "edge-actions")
			terminal := startDNSNoticeIntegrationNode(t, pki, Config{ProcessorID: "notice-terminal", RelayOrigins: map[string][]string{"notice-middle": {"notice-hunter"}}, EventIngressProfile: "memory_only", CommandExecutorConfig: &CommandExecutorConfig{TunnelingCommand: "printf '%s\\n' %domain% >> " + shellEscape(terminalOutput)}}, nil)
			config := Config{ProcessorID: "notice-middle", UpstreamAddr: terminal.address, UpstreamForwardMode: mode, UpstreamEventDeliveryProfile: "memory_only", UpstreamEventSpoolDirectory: t.TempDir()}
			if mode == "events" {
				config.CommandExecutorConfig = &CommandExecutorConfig{TunnelingCommand: "printf '%s\\n' %domain% >> " + shellEscape(edgeOutput)}
			}
			middle := startDNSNoticeIntegrationNode(t, pki, config, nil)
			require.Eventually(t, middle.processor.upstreamManager.IsConnected, 5*time.Second, time.Millisecond)
			sendDNSNoticeIntegrationPacket(t, middle, pki, dnsNoticeIntegrationPacket(t, 0))
			got := nextDNSNoticeIntegration(t, terminal)
			owner, actionOutput := terminal, terminalOutput
			if mode == "events" {
				owner, actionOutput = middle, edgeOutput
				original := nextDNSNoticeIntegration(t, middle)
				require.Equal(t, original.Envelope().EventID, got.Envelope().EventID)
				require.Zero(t, terminal.processor.GetNoticeStats().Emitted)
				require.Equal(t, NoticeCommandSinkStats{}, terminal.processor.GetNoticeStats().Commands)
				_, err := os.Stat(terminalOutput)
				require.ErrorIs(t, err, os.ErrNotExist)
			} else {
				require.Zero(t, middle.processor.GetNoticeStats().Emitted)
				require.Nil(t, middle.processor.noticeCommands)
				require.Empty(t, middle.sink.notices)
			}
			require.Equal(t, owner.processor.noticeAuthority(), got.DetectorNodeID)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			require.NoError(t, owner.processor.noticeCommands.Flush(ctx))
			content, err := os.ReadFile(actionOutput)
			require.NoError(t, err)
			require.Equal(t, "tunnel.example\n", string(content))
			require.EqualValues(t, 1, owner.processor.GetNoticeStats().Commands.Completed)
		})
	}
}
