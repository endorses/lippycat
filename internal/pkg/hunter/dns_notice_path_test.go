//go:build all

package hunter

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	eventsv1 "github.com/endorses/lippycat/api/gen/events/v1"
	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/eventconfig"
	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/endorses/lippycat/internal/pkg/events/protoadapter"
	"github.com/endorses/lippycat/internal/pkg/failover"
	"github.com/endorses/lippycat/internal/pkg/processor"
	"github.com/endorses/lippycat/internal/testutil/eventfixture"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/protobuf/proto"
)

func dnsNoticeHunterPolicy() *eventconfig.Config {
	policy := eventconfig.Default()
	dns := policy.EffectiveDNS()
	dns.DetectTunneling, dns.Threshold, dns.Debounce = true, 0.01, time.Minute
	policy.DNS = &dns
	return &policy
}

func dnsNoticeHunterPacket(t *testing.T) capture.PacketInfo {
	t.Helper()
	dns := &layers.DNS{ID: 42, RD: true, Questions: []layers.DNSQuestion{{Name: []byte("a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6.tunnel.example"), Type: layers.DNSTypeTXT, Class: layers.DNSClassIN}}}
	encoded := gopacket.NewSerializeBuffer()
	require.NoError(t, gopacket.SerializeLayers(encoded, gopacket.SerializeOptions{FixLengths: true}, dns))
	packet, err := eventfixture.NetworkDatagram("192.0.2.10", "192.0.2.53", 42000, 53, encoded.Bytes(), eventfixture.BaseTime)
	require.NoError(t, err)
	return packet
}

func startDNSNoticeHunter(t *testing.T, address, certificate, key string) (*Hunter, func()) {
	t.Helper()
	h, err := New(Config{HunterID: "edge", ProcessorAddr: address, ForwardMode: "events", EventAnalysis: dnsNoticeHunterPolicy(), EventDeliveryProfile: "memory_only", EventSpoolDir: t.TempDir(), BufferSize: 16, BatchSize: 1, BatchTimeout: time.Millisecond,
		TLSEnabled: true, TLSCAFile: certificate, TLSCertFile: certificate, TLSKeyFile: key, NoFilterPolicy: "allow", Failover: failover.Config{AttemptTimeout: time.Second, RetryInitial: 10 * time.Millisecond, RetryMax: 20 * time.Millisecond}})
	require.NoError(t, err)
	// Keep actual lifecycle, filtering, runtime, spooling and transport; only
	// supply generated input through the capture queue instead of a device.
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
			t.Error("DNS notice hunter did not join after cancellation")
		}
		require.NoError(t, h.Close())
	})
	t.Cleanup(stop)
	return h, stop
}

type dnsNoticeHunterSink struct{ notices chan events.NoticeEvent }

func (s *dnsNoticeHunterSink) HandleEvent(ctx context.Context, event events.Event) error {
	select {
	case s.notices <- event.(events.NoticeEvent):
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (*dnsNoticeHunterSink) Flush(context.Context) error { return nil }
func (*dnsNoticeHunterSink) Close(context.Context) error { return nil }

func TestDNSNoticeActualHunterTransportWritesNoticeLog(t *testing.T) {
	_, certificate, key, _ := rawIntegrationCertificate(t)
	directory := t.TempDir()
	receiver, err := processor.New(processor.Config{ProcessorID: "receiver", ListenAddr: "127.0.0.1:0", FilterFile: filepath.Join(t.TempDir(), "managed", "filters.yaml"), TLSEnabled: true, TLSClientAuth: true, TLSCAFile: certificate, TLSCertFile: certificate, TLSKeyFile: key,
		EventIngressProfile: "memory_only", EventQueueSize: 32, GracefulShutdownTimeout: 100 * time.Millisecond, LogConfig: &processor.StructuredLogConfig{Enabled: true, Directory: directory, Format: "json", Streams: []string{"notice"}, QueueSize: 16}})
	require.NoError(t, err)
	sink := &dnsNoticeHunterSink{notices: make(chan events.NoticeEvent, 4)}
	require.NoError(t, receiver.RegisterEventSink(sink, events.KindNotice))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- receiver.Start(ctx) }()
	stopReceiver := sync.OnceFunc(func() {
		cancel()
		select {
		case err := <-done:
			require.NoError(t, err)
		case <-time.After(10 * time.Second):
			t.Error("DNS notice receiver did not join after cancellation")
		}
	})
	t.Cleanup(stopReceiver)
	require.Eventually(t, func() bool { return receiver.ListenAddr() != "" }, 5*time.Second, time.Millisecond)
	h, stopHunter := startDNSNoticeHunter(t, receiver.ListenAddr(), certificate, key)
	require.Eventually(t, func() bool {
		selection := h.statsCollector.ToProto(0).GetProcessorSelection()
		return selection.GetState() == "connected" && selection.GetActiveEndpoint() == receiver.ListenAddr()
	}, 5*time.Second, time.Millisecond)
	packet := dnsNoticeHunterPacket(t)
	require.True(t, h.captureManager.GetPacketBuffer().Send(packet))
	var notice events.NoticeEvent
	select {
	case notice = <-sink.notices:
	case <-time.After(10 * time.Second):
		t.Fatal("actual hunter transport did not deliver the local DNS notice")
	}
	require.True(t, events.HasValidDeliveryIdentity(notice.Envelope()))
	require.Equal(t, "edge", notice.Envelope().NodeID)
	require.Equal(t, "edge", notice.DetectorNodeID)
	require.NotEmpty(t, notice.DetectorGeneration)
	require.Equal(t, packet.Packet.Metadata().Timestamp, notice.Envelope().Timestamp)
	require.Equal(t, "tunnel.example", notice.DNS.Domain)
	require.Zero(t, receiver.GetStats().TotalPacketsReceived, "event transport must not reanalyze a raw packet at the receiver")
	require.Zero(t, receiver.GetNoticeStats().Emitted)
	require.Zero(t, receiver.GetNoticeStats().Commands.Completed)
	stopHunter()
	// Production shutdown drains dispatcher/coalescer/log queues before reading.
	stopReceiver()
	content, err := os.ReadFile(filepath.Join(directory, "notice.log"))
	require.NoError(t, err)
	lines := strings.Split(strings.TrimSpace(string(content)), "\n")
	require.Len(t, lines, 1)
	var record map[string]any
	require.NoError(t, json.Unmarshal([]byte(lines[0]), &record))
	require.Equal(t, notice.Envelope().EventID, record["event_id"])
	require.Equal(t, "edge", record["node_id"])
	require.Equal(t, "edge", record["detector_node_id"])
	require.Equal(t, "tunnel.example", record["domain"])
	require.Equal(t, events.NoticeDetectorDNSTunneling, record["detector"])
	require.Empty(t, sink.notices)
}

type dnsNoticeLegacyPeer struct {
	management.UnimplementedManagementServiceServer
	eventsv1.UnimplementedEventServiceServer
	registrations chan *management.HunterRegistration
	streams       atomic.Uint32
}

func (s *dnsNoticeLegacyPeer) RegisterHunter(_ context.Context, req *management.HunterRegistration) (*management.RegistrationResponse, error) {
	select {
	case s.registrations <- proto.Clone(req).(*management.HunterRegistration):
	default:
	}
	var supported []int32
	for _, kind := range protoadapter.SupportedKindIDs(false) {
		if kind != int32(eventsv1.EventKind_EVENT_KIND_NOTICE) {
			supported = append(supported, kind)
		}
	}
	return &management.RegistrationResponse{Accepted: true, AssignedId: req.HunterId, AcceptedForwardingMode: management.ForwardingMode_FORWARDING_MODE_EVENTS, AcceptedEventApiMajor: 1, AcceptedSemanticProfileRevision: 1, AcceptedEventKinds: supported}, nil
}
func (s *dnsNoticeLegacyPeer) StreamEvents(eventsv1.EventService_StreamEventsServer) error {
	s.streams.Add(1)
	return errors.New("notice-incapable peer must not receive an event stream")
}

func TestDNSNoticeActualHunterRejectsPeerWithoutNoticeSupport(t *testing.T) {
	pair, certificate, key, roots := rawIntegrationCertificate(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	service := &dnsNoticeLegacyPeer{registrations: make(chan *management.HunterRegistration, 1)}
	server := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{pair}, ClientCAs: roots, ClientAuth: tls.RequireAndVerifyClientCert})))
	management.RegisterManagementServiceServer(server, service)
	eventsv1.RegisterEventServiceServer(server, service)
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	t.Cleanup(func() {
		server.Stop()
		require.NoError(t, <-done)
	})
	h, _ := startDNSNoticeHunter(t, listener.Addr().String(), certificate, key)
	select {
	case registration := <-service.registrations:
		require.Contains(t, registration.EventForwarding.EventKinds, int32(eventsv1.EventKind_EVENT_KIND_NOTICE))
		require.Contains(t, registration.EventForwarding.StatefulAnalysisFeatures, protoadapter.DNSNoticeProductionFeature)
	case <-time.After(5 * time.Second):
		t.Fatal("actual hunter did not negotiate its DNS notice production requirement")
	}
	want := fmt.Sprintf("required event kind %d was not accepted", eventsv1.EventKind_EVENT_KIND_NOTICE)
	require.Eventually(t, func() bool {
		selection := h.statsCollector.ToProto(0).GetProcessorSelection()
		return selection.GetActiveEndpoint() == "" && strings.Contains(selection.GetReason(), want)
	}, 5*time.Second, time.Millisecond)
	require.Zero(t, service.streams.Load(), "an incapable peer cannot silently discard canonical findings")
}
