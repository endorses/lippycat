//go:build all

package hunter

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/endorses/lippycat/internal/pkg/failover"
	"github.com/endorses/lippycat/internal/pkg/processor"
	"github.com/endorses/lippycat/internal/testutil/eventfixture"
	"github.com/google/gopacket/pcapgo"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// Only the capture device is replaced by generated input. Both sides still run
// their production lifecycle, registration, policy, analysis, and transport.
type failoverEventSink struct{ received chan events.Event }

func (s *failoverEventSink) HandleEvent(_ context.Context, event events.Event) error {
	select {
	case s.received <- event:
		return nil
	default:
		return errors.New("failover test event queue overflow")
	}
}
func (*failoverEventSink) Flush(context.Context) error { return nil }
func (*failoverEventSink) Close(context.Context) error { return nil }

func (s *failoverEventSink) nextNTP(t *testing.T) events.NTPEvent {
	t.Helper()
	select {
	case event := <-s.received:
		require.IsType(t, events.NTPEvent{}, event)
		return event.(events.NTPEvent)
	case <-time.After(10 * time.Second):
		t.Fatal("production receiver did not emit the injected NTP observation")
		return events.NTPEvent{}
	}
}

type failoverProcessorRuntime struct {
	p       *processor.Processor
	config  processor.Config
	address string
	sink    *failoverEventSink
	client  management.ManagementServiceClient
	stop    func()
}

func startFailoverProcessor(t *testing.T, config processor.Config, pair tls.Certificate, roots *x509.CertPool) *failoverProcessorRuntime {
	t.Helper()
	p, err := processor.New(config)
	require.NoError(t, err)
	sink := &failoverEventSink{received: make(chan events.Event, 16)}
	require.NoError(t, p.RegisterEventSink(sink, events.KindNTP))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- p.Start(ctx) }()
	var once sync.Once
	stop := func() {
		once.Do(func() {
			cancel()
			select {
			case err := <-done:
				require.NoError(t, err)
			case <-time.After(10 * time.Second):
				t.Error("processor did not join its lifecycle after cancellation")
			}
		})
	}
	t.Cleanup(stop)
	require.Eventually(t, func() bool { return p.ListenAddr() != "" }, 5*time.Second, time.Millisecond)
	address := p.ListenAddr()
	conn, err := grpc.NewClient(address, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
		MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{pair}, RootCAs: roots,
	})))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, conn.Close()) })
	client := management.NewManagementServiceClient(conn)
	require.Eventually(t, func() bool {
		query, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()
		_, err := client.GetHunterStatus(query, &management.StatusRequest{})
		return err == nil
	}, 5*time.Second, time.Millisecond)
	return &failoverProcessorRuntime{p, config, address, sink, client, stop}
}

func installFailoverFilter(t *testing.T, receiver *failoverProcessorRuntime) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result, err := receiver.client.UpdateFilter(ctx, &management.Filter{
		Id: "capture-fixture", Type: management.FilterType_FILTER_IP_ADDRESS,
		Pattern: "192.0.2.0/24", Enabled: true,
	})
	require.NoError(t, err)
	require.NotNil(t, result)
}

func waitFailoverSelection(t *testing.T, h *Hunter, address string, failovers uint64) {
	t.Helper()
	require.Eventually(t, func() bool {
		selection := h.statsCollector.ToProto(uint32(h.filterManager.GetFilterCount())).GetProcessorSelection()
		return selection.GetState() == "connected" && selection.GetActiveEndpoint() == address && selection.GetFailoverCount() == failovers
	}, 10*time.Second, time.Millisecond)
	filters := h.filterManager.GetFilters()
	require.Len(t, filters, 1)
	require.Equal(t, "capture-fixture", filters[0].Id)
	require.Equal(t, "192.0.2.0/24", filters[0].Pattern)
	require.True(t, filters[0].Enabled)
}

func TestHunterFailoverIndependentProcessorDeployment(t *testing.T) {
	for _, mode := range []string{"packets", "events"} {
		t.Run(mode, func(t *testing.T) {
			pair, certificate, key, roots := rawIntegrationCertificate(t)
			makeConfig := func(id string) processor.Config {
				return processor.Config{
					ProcessorID: id, ListenAddr: "127.0.0.1:0",
					FilterFile: filepath.Join(t.TempDir(), "managed", "filters.yaml"),
					WriteFile:  filepath.Join(t.TempDir(), "received.pcap"),
					TLSEnabled: true, TLSClientAuth: true, TLSCAFile: certificate,
					TLSCertFile: certificate, TLSKeyFile: key,
					EventIngressProfile: "memory_only", EventQueueSize: 32,
					GracefulShutdownTimeout: 100 * time.Millisecond,
				}
			}
			primary := startFailoverProcessor(t, makeConfig("primary"), pair, roots)
			backup := startFailoverProcessor(t, makeConfig("backup"), pair, roots)
			installFailoverFilter(t, primary)
			installFailoverFilter(t, backup)
			h, err := New(Config{
				HunterID: "edge", Processors: []failover.Endpoint{{Address: primary.address}, {Address: backup.address}},
				Failover:   failover.Config{AttemptTimeout: time.Second, ReconnectAttempts: 0, RetryInitial: 10 * time.Millisecond, RetryMax: 20 * time.Millisecond},
				BufferSize: 32, BatchSize: 1, BatchTimeout: 10 * time.Millisecond, NoFilterPolicy: "deny",
				ForwardMode: mode, EventDeliveryProfile: "memory_only", EventSpoolDir: t.TempDir(),
				TLSEnabled: true, TLSCAFile: certificate, TLSCertFile: certificate, TLSKeyFile: key,
			})
			require.NoError(t, err)
			require.NoError(t, h.captureManager.PrepareBuffer())
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan error, 1)
			go func() { done <- h.Start(ctx) }()
			var stopHunter sync.Once
			t.Cleanup(func() {
				stopHunter.Do(func() {
					cancel()
					select {
					case err := <-done:
						require.NoError(t, err)
					case <-time.After(10 * time.Second):
						t.Error("hunter did not join its lifecycle after cancellation")
					}
					require.NoError(t, h.Close())
				})
			})
			waitFailoverSelection(t, h, primary.address, 0)
			packets, err := eventfixture.NetworkMessages()
			require.NoError(t, err)
			request, response := packets[3], packets[4]
			require.True(t, h.captureManager.GetPacketBuffer().Send(request))
			first := primary.sink.nextNTP(t)
			require.Equal(t, events.AssociationRequest, first.Association)
			require.Equal(t, "edge", first.Envelope().NodeID)
			require.Equal(t, "edge", first.Envelope().Provenance.CaptureSource)
			require.Equal(t, "fixture0", first.Envelope().Provenance.InterfaceName)
			require.Equal(t, request.Packet.Metadata().Timestamp.UnixNano(), first.Envelope().Timestamp.UnixNano())
			require.NotEmpty(t, first.Envelope().EventID)
			require.NotEmpty(t, first.Envelope().ProducerSessionID)
			primary.stop()
			waitFailoverSelection(t, h, backup.address, 1)
			require.True(t, h.captureManager.GetPacketBuffer().Send(response))
			second := backup.sink.nextNTP(t)
			require.Equal(t, "edge", second.Envelope().NodeID)
			require.Equal(t, "edge", second.Envelope().Provenance.CaptureSource)
			require.Equal(t, response.Packet.Metadata().Timestamp.UnixNano(), second.Envelope().Timestamp.UnixNano())
			require.Equal(t, first.Transmit.Raw, second.Origin.Raw)
			if mode == "events" {
				// Analysis belongs to the hunter; switching destinations must not
				// reauthor observations or discard its still-live NTP association.
				require.Equal(t, events.AssociationUnique, second.Association)
				require.Equal(t, first.Envelope().ProducerSessionID, second.Envelope().ProducerSessionID)
				require.Greater(t, second.Envelope().EventSequence, first.Envelope().EventSequence)
				require.Zero(t, primary.p.GetStats().TotalPacketsReceived)
				require.Zero(t, backup.p.GetStats().TotalPacketsReceived)
			} else {
				// Independent processors have independent protocol state. A response
				// without its locally observed request must remain unmatched.
				require.Equal(t, events.AssociationMissing, second.Association)
				require.NotEqual(t, first.Envelope().ProducerSessionID, second.Envelope().ProducerSessionID)
				require.Equal(t, []string{"primary"}, first.Envelope().Provenance.ProcessorNodeIDs)
				require.Equal(t, []string{"backup"}, second.Envelope().Provenance.ProcessorNodeIDs)
				require.EqualValues(t, 1, primary.p.GetStats().TotalPacketsReceived)
				require.EqualValues(t, 1, backup.p.GetStats().TotalPacketsReceived)
			}
			// Recover the preferred endpoint at the same address, then demonstrate
			// useful traffic still goes to the working backup (no automatic failback).
			recoveredConfig := primary.config
			recoveredConfig.ListenAddr = primary.address
			recoveredConfig.WriteFile = filepath.Join(t.TempDir(), "recovered.pcap")
			recovered := startFailoverProcessor(t, recoveredConfig, pair, roots)
			request.Packet.Metadata().Timestamp = request.Packet.Metadata().Timestamp.Add(2 * time.Second)
			require.True(t, h.captureManager.GetPacketBuffer().Send(request))
			third := backup.sink.nextNTP(t)
			require.Equal(t, request.Packet.Metadata().Timestamp.UnixNano(), third.Envelope().Timestamp.UnixNano())
			waitFailoverSelection(t, h, backup.address, 1)
			require.Zero(t, recovered.p.GetStats().TotalPacketsReceived)
			select {
			case unexpected := <-recovered.sink.received:
				t.Fatalf("recovered primary unexpectedly received %s", unexpected.Kind())
			default:
			}
			backup.stop()
			if mode == "packets" {
				assertFailoverPCAP(t, primary.config.WriteFile, [][]byte{packets[3].Packet.Data()})
				assertFailoverPCAP(t, backup.config.WriteFile, [][]byte{response.Packet.Data(), request.Packet.Data()})
			}
		})
	}
}

func assertFailoverPCAP(t *testing.T, path string, expected [][]byte) {
	t.Helper()
	file, err := os.Open(path)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, file.Close()) })
	reader, err := pcapgo.NewReader(file)
	require.NoError(t, err)
	for _, want := range expected {
		got, _, err := reader.ReadPacketData()
		require.NoError(t, err)
		require.Equal(t, want, got)
	}
	_, _, err = reader.ReadPacketData()
	require.ErrorIs(t, err, io.EOF)
}
