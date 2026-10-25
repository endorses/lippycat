//go:build tui || all

package tui

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/endorses/lippycat/internal/pkg/offline"
	"github.com/endorses/lippycat/internal/pkg/tui/store"
	"github.com/endorses/lippycat/internal/testutil/noticefixture"
	"github.com/stretchr/testify/require"
)

func offlineSinkMetadataKinds() []events.Event {
	notice := noticefixture.Event()
	env := notice.Envelope()
	env.Partial, env.CaptureScope = false, events.CaptureScopeFull
	conn := events.NewConnEvent(env)
	conn.Service, conn.Duration = "dns", time.Second
	dns := events.NewDNSEvent(env)
	dns.Query, dns.QClass, dns.QType = "example.test", 1, 1
	tls := events.NewTLSEvent(env)
	tls.ServerName, tls.ClientHelloCount, tls.ECHOfferedCount = "public.example", 2, 1
	http := events.NewHTTPEvent(env)
	http.Method, http.URI = "GET", "/original"
	smtp := events.NewSMTPEvent(env)
	smtp.MailFrom, smtp.Recipients = "sender@example.test", []string{"recipient@example.test"}
	file := events.NewFileMetadataEvent(env)
	file.FileID, file.SeenBytes, file.MIMEType = "Fmetadata", 200, "text/plain"
	dhcp := events.NewDHCPEvent(env)
	dhcp.Operation, dhcp.MessageType, dhcp.HardwareType = 1, 1, 1
	dhcp.HardwareAddress = []byte{0, 1, 2, 3, 4, 5}
	dhcp.ClientAddress, dhcp.OfferedAddress, dhcp.NextServerAddress, dhcp.RelayAddress = netip.IPv4Unspecified(), netip.IPv4Unspecified(), netip.IPv4Unspecified(), netip.IPv4Unspecified()
	dhcp.Association = events.AssociationRequest
	ntp := events.NewNTPEvent(env)
	ntp.Version, ntp.Mode, ntp.Association = 4, 3, events.AssociationRequest
	host := events.NewKnownHostEvent(env)
	host.Host, host.Evidence = env.Flow.SourceAddress, events.EvidenceUDPBidirectional
	service := events.NewKnownServiceEvent(env)
	service.Host, service.Port, service.Transport, service.Protocol, service.Evidence = env.Flow.DestinationAddress, 53, 17, "dns", events.EvidenceDNSExchange
	radius := events.NewRADIUSEvent(env)
	radius.Code, radius.Length, radius.Attributes = 1, 20, []string{"1:hex:616c696365"}
	return []events.Event{conn, dns, tls, http, smtp, file, dhcp, ntp, host, service, radius, notice}
}

func TestOfflineEventSinkPreservesAllKindsAndAmendedSnapshots(t *testing.T) {
	storage := testOfflineStorage(t)
	builder, err := storage.NewEventBuilder(17)
	require.NoError(t, err)
	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)
	retained := store.NewEventStore(1)
	sink := newOfflineEventSink(builder, retained, cancel)
	dispatcher, err := events.NewDispatcher(events.Config{QueueSize: 2, SinkQueueSize: 2})
	require.NoError(t, err)
	require.NoError(t, dispatcher.Register(sink))
	require.NoError(t, dispatcher.Start(ctx))
	want := offlineSinkMetadataKinds()
	for _, event := range want {
		require.True(t, dispatcher.EnqueueLossless(context.Background(), event))
	}
	amended := want[3].(events.HTTPEvent)
	amended.URI = "/amended"
	want = append(want, amended)
	require.True(t, dispatcher.EnqueueLossless(context.Background(), amended))
	// The metadata projection deliberately excludes file bodies and nil values.
	require.NoError(t, sink.HandleEvent(ctx, nil))
	require.NoError(t, sink.HandleEvent(ctx, (*events.DNSEvent)(nil)))
	require.NoError(t, sink.HandleEvent(ctx, events.NewFileContentEvent(noticefixture.Event().Envelope())))
	require.NoError(t, dispatcher.Close(context.Background()))
	require.NoError(t, sink.Err())
	require.NoError(t, sink.Close(context.Background()))
	require.Nil(t, context.Cause(ctx))
	dataset, err := builder.Finish(context.Background())
	require.NoError(t, err)
	defer func() { require.NoError(t, dataset.Close()) }()
	require.EqualValues(t, len(want), dataset.Count())
	require.EqualValues(t, 1, retained.Stats().Retained)
	require.EqualValues(t, len(want), retained.Stats().Arrived)
	query, err := offline.AllEvents(context.Background(), dataset, offline.Token{Dataset: 17, Query: 1})
	require.NoError(t, err)
	defer func() { require.NoError(t, query.Close()) }()
	var index int
	require.NoError(t, query.Iterate(context.Background(), func(record offline.EventRecord) error {
		require.EqualValues(t, index+1, record.ID)
		require.Equal(t, want[index], record.Event)
		index++
		return nil
	}))
	require.Equal(t, len(want), index)
	require.Equal(t, want[3].Envelope().EventID, amended.Envelope().EventID)
}

func TestOfflineEventSinkFailureCancelsAndSurvivesDrain(t *testing.T) {
	storage, err := offline.NewStorage(offline.ResourceLimits{Directory: t.TempDir(), DiskBytes: 96, CacheBytes: 1 << 20, MaxRecordBytes: 96, MaxSources: 1})
	require.NoError(t, err)
	defer func() { require.NoError(t, storage.Close()) }()
	builder, err := storage.NewEventBuilder(3)
	require.NoError(t, err)
	defer func() { require.NoError(t, builder.Abort()) }()
	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)
	retained := store.NewEventStore(2)
	sink := newOfflineEventSink(builder, retained, cancel)
	dispatcher, err := events.NewDispatcher(events.Config{QueueSize: 2, SinkQueueSize: 2})
	require.NoError(t, err)
	require.NoError(t, dispatcher.Register(sink))
	require.NoError(t, dispatcher.Start(ctx))
	require.True(t, dispatcher.EnqueueLossless(context.Background(), offlineSinkMetadataKinds()[0]))
	require.ErrorContains(t, dispatcher.Close(context.Background()), "persist offline event history")
	require.ErrorContains(t, sink.Err(), "record")
	require.ErrorIs(t, context.Cause(ctx), sink.Err())
	var terminal interface{ TerminalSinkError() bool }
	require.ErrorAs(t, sink.Err(), &terminal)
	require.True(t, terminal.TerminalSinkError())
	require.ErrorIs(t, sink.Flush(context.Background()), sink.Err())
	require.ErrorIs(t, sink.Close(context.Background()), sink.Err())
	require.ErrorIs(t, sink.HandleEvent(context.Background(), offlineSinkMetadataKinds()[1]), sink.Err())
	require.Zero(t, retained.Stats().Arrived)
	_, err = builder.Finish(context.Background())
	require.Error(t, err)
	require.False(t, errors.Is(sink.Err(), context.Canceled), "the original persistence cause is retained")
}
