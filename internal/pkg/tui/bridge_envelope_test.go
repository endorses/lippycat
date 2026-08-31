//go:build tui || all

package tui

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/endorses/lippycat/internal/pkg/pipeline"
	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/endorses/lippycat/internal/testutil/eventfixture"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/require"
)

func TestNormalizeCaptureStreamPreservesEnvelopeProvenance(t *testing.T) {
	timestamp := time.Date(2026, time.August, 29, 12, 34, 56, 789, time.UTC)
	data := goldenUDPPacket(t, 53000, 53, []byte{0, 1, 2, 3})
	packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)
	packet.Metadata().CaptureInfo = gopacket.CaptureInfo{
		Timestamp:     timestamp,
		CaptureLength: len(data),
		Length:        len(data) + 8,
	}

	input := make(chan capture.PacketInfo, 1)
	input <- capture.PacketInfo{Packet: packet, Interface: "capture.pcap", SourcePath: "/captures/a/capture.pcap", LinkType: layers.LinkTypeEthernet}
	close(input)

	envelopes := NormalizeCaptureStream(context.Background(), input, pipeline.SourcePCAPReplay)
	envelope := <-envelopes
	require.NotNil(t, envelope)
	require.Equal(t, pipeline.SourcePCAPReplay, envelope.Source.Kind)
	require.Equal(t, "capture.pcap", envelope.Source.InterfaceName)
	require.Equal(t, "/captures/a/capture.pcap", envelope.Source.InputFile)
	require.Equal(t, layers.LinkTypeEthernet, envelope.LinkType)
	require.Equal(t, timestamp, envelope.CaptureTime)
	require.Equal(t, len(data), envelope.CaptureLength)
	require.Equal(t, len(data)+8, envelope.OriginalLength)
	require.True(t, bytes.Equal(data, envelope.Data))
	_, ok := <-envelopes
	require.False(t, ok)
}

func TestEnvelopeBridgePublishesOrderedPacketsThroughLocalEventHandler(t *testing.T) {
	ResetBridgeStats()
	ClearPendingPackets()
	ResetTUIReady()
	SignalTUIReady()
	SetVoIPModeEnabled(false)

	base := time.Date(2026, time.August, 29, 13, 0, 0, 0, time.UTC)
	envelopes := make(chan *pipeline.PacketEnvelope, 3)
	for i := range 3 {
		data := goldenUDPPacket(t, layers.UDPPort(53000+i), 53, []byte{byte(i)})
		envelopes <- &pipeline.PacketEnvelope{
			Data:           data,
			LinkType:       layers.LinkTypeEthernet,
			CaptureTime:    base.Add(time.Duration(i) * time.Millisecond),
			CaptureLength:  len(data),
			OriginalLength: len(data),
			Source:         pipeline.SourceProvenance{Kind: pipeline.SourcePCAPReplay, InterfaceName: "ordered.pcap"},
		}
	}
	close(envelopes)

	StartEnvelopeBridge(envelopes, nil, NewPauseSignal(), nil, true, nil)
	got := pendingPackets.drainPackets(3)
	require.Len(t, got, 3)
	for i := range got {
		require.Equal(t, base.Add(time.Duration(i)*time.Millisecond), got[i].Timestamp)
		require.Equal(t, "ordered.pcap", got[i].Interface)
	}
	require.Equal(t, int64(3), GetBridgeStats().PacketsDisplayed)

	// Compile-time and behavioral coverage for the shared local/remote boundary.
	var handler types.EventHandler = newLocalTUIEventHandler(nil, true)
	handler.OnPacketBatch([]types.PacketDisplay{{Timestamp: base.Add(4 * time.Millisecond)}})
	require.Len(t, pendingPackets.drainPackets(1), 1)
}

func TestEnvelopeBridgePublishesOfflineEventsWithFileProvenanceBeforeEOF(t *testing.T) {
	ResetBridgeStats()
	ClearPendingPackets()
	ResetTUIReady()
	SignalTUIReady()
	SetVoIPModeEnabled(false)

	timestamp := time.Date(2026, time.August, 30, 15, 0, 0, 0, time.UTC)
	data := goldenDNSPacket(t)
	envelopes := make(chan *pipeline.PacketEnvelope, 1)
	envelopes <- &pipeline.PacketEnvelope{
		Data:           data,
		LinkType:       layers.LinkTypeEthernet,
		CaptureTime:    timestamp,
		CaptureLength:  len(data),
		OriginalLength: len(data),
		Source: pipeline.SourceProvenance{
			Kind: pipeline.SourcePCAPReplay, InterfaceName: "fixture.pcap", InterfaceIndex: 7,
		},
	}
	close(envelopes)

	var batches []types.EventBatch
	StartEnvelopeBridge(envelopes, nil, NewPauseSignal(), nil, true, nil, LocalEventAnalysisOptions{
		NodeID: "watch-local", SourceOrdering: []string{"fixture.pcap"},
		CaptureScope: events.CaptureScopeFiltered, Partial: true,
		deliver: func(batch types.EventBatch) {
			batches = append(batches, batch)
		},
	})

	var dnsEvent events.Event
	for _, batch := range batches {
		for _, event := range batch.Events {
			if event.Kind() == events.KindDNS {
				dnsEvent = event
			}
		}
	}
	require.NotNil(t, dnsEvent)
	envelope := dnsEvent.Envelope()
	require.True(t, timestamp.Equal(envelope.Timestamp))
	require.Equal(t, "watch-local", envelope.NodeID)
	require.Equal(t, "pcap", envelope.Provenance.CaptureSource)
	require.Equal(t, "fixture.pcap", envelope.Provenance.InputFile)
	require.Equal(t, uint32(7), envelope.Provenance.InterfaceIndex)
	require.Equal(t, events.CaptureScopeFiltered, envelope.CaptureScope)
	require.True(t, envelope.Partial)
	require.NotEmpty(t, envelope.EventID)
	require.NotEmpty(t, envelope.ProducerSessionID)
	require.NotZero(t, envelope.EventSequence)
}

func TestWatchLiveAndFileSharedFixtureProduceEquivalentHTTPEvents(t *testing.T) {
	type result struct {
		event events.HTTPEvent
		conn  events.ConnEvent
		loss  uint64
	}
	run := func(t *testing.T, preserveAll bool, kind pipeline.SourceKind, source string) result {
		t.Helper()
		ResetBridgeStats()
		ClearPendingPackets()
		ResetTUIReady()
		SignalTUIReady()
		SetVoIPModeEnabled(false)
		envelopes, err := eventfixture.Envelopes(kind, source)
		require.NoError(t, err)
		input := make(chan *pipeline.PacketEnvelope, len(envelopes))
		for _, envelope := range envelopes {
			input <- envelope
		}
		close(input)
		var batches []types.EventBatch
		StartEnvelopeBridge(input, nil, NewPauseSignal(), nil, preserveAll, nil, LocalEventAnalysisOptions{
			NodeID: "watch-local", SourceOrdering: []string{source},
			deliver: func(batch types.EventBatch) { batches = append(batches, batch) },
		})
		var got result
		var count int
		for _, batch := range batches {
			for _, loss := range batch.Losses {
				got.loss += loss.Count
			}
			for _, event := range batch.Events {
				switch event.Kind() {
				case events.KindHTTP:
					got.event = event.(events.HTTPEvent)
					count++
				case events.KindConn:
					got.conn = event.(events.ConnEvent)
				}
			}
		}
		require.Equal(t, 1, count)
		require.Zero(t, got.loss)
		return got
	}

	live := run(t, false, pipeline.SourceLiveCapture, "eth-test")
	file := run(t, true, pipeline.SourcePCAPReplay, "/captures/phase4.pcap")
	for _, event := range []events.HTTPEvent{live.event, file.event} {
		require.Equal(t, "GET", event.Method)
		require.Equal(t, "/phase4", event.URI)
		require.Equal(t, "parity.example.test", event.Host)
		require.True(t, eventfixture.BaseTime.Add(2*time.Second).Equal(event.Envelope().Timestamp))
	}
	require.Equal(t, "HTTP", live.conn.Service)
	require.Equal(t, "HTTP", file.conn.Service)
	require.Equal(t, "live", live.event.Envelope().Provenance.CaptureSource)
	require.Equal(t, "eth-test", live.event.Envelope().Provenance.InterfaceName)
	require.Equal(t, "pcap", file.event.Envelope().Provenance.CaptureSource)
	require.Equal(t, "/captures/phase4.pcap", file.event.Envelope().Provenance.InputFile)
}

func TestWatchFileEventIdentityTracksInputAndAnalysisProfile(t *testing.T) {
	session := func(t *testing.T, inputIdentity, profile string) string {
		t.Helper()
		ResetBridgeStats()
		ClearPendingPackets()
		ResetTUIReady()
		SignalTUIReady()
		envelopes, err := eventfixture.Envelopes(pipeline.SourcePCAPReplay, "fixture.pcap")
		require.NoError(t, err)
		input := make(chan *pipeline.PacketEnvelope, len(envelopes))
		for _, envelope := range envelopes {
			input <- envelope
		}
		close(input)
		var producerSession string
		StartEnvelopeBridge(input, nil, NewPauseSignal(), nil, true, nil, LocalEventAnalysisOptions{
			NodeID: "watch-local", InputIdentity: inputIdentity, AnalysisProfile: profile,
			SourceOrdering: []string{"fixture.pcap"},
			deliver: func(batch types.EventBatch) {
				if producerSession == "" && len(batch.Events) != 0 {
					producerSession = batch.Events[0].Envelope().ProducerSessionID
				}
			},
		})
		require.NotEmpty(t, producerSession)
		return producerSession
	}

	baseline := session(t, "sha256:input-a", "watch-eventanalysis-v1|filter=tcp")
	require.Equal(t, baseline, session(t, "sha256:input-a", "watch-eventanalysis-v1|filter=tcp"))
	require.NotEqual(t, baseline, session(t, "sha256:input-b", "watch-eventanalysis-v1|filter=tcp"))
	require.NotEqual(t, baseline, session(t, "sha256:input-a", "watch-eventanalysis-v1|filter=udp"))
}
