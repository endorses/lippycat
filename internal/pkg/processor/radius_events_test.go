//go:build processor || tap || all

package processor

import (
	"context"
	"os"
	"testing"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/endorses/lippycat/internal/pkg/pipeline/grpcadapter"
	"github.com/endorses/lippycat/internal/pkg/protocolmeta"
	"github.com/endorses/lippycat/internal/pkg/radius"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcapgo"
	"github.com/stretchr/testify/require"
)

func TestRADIUSEventUsesValidatedPacket(t *testing.T) {
	file, err := os.Open("../../../testdata/radius/acceptance.pcap")
	require.NoError(t, err)
	defer func() { require.NoError(t, file.Close()) }()
	reader, err := pcapgo.NewReader(file)
	require.NoError(t, err)
	raw, ci, err := reader.ReadPacketData()
	require.NoError(t, err)
	packet := gopacket.NewPacket(raw, reader.LinkType(), gopacket.Default)
	packet.Metadata().CaptureInfo = ci
	ingress, err := radius.NewCaptureProcessor(radius.CaptureScope{OriginNodeID: "hunter"})
	require.NoError(t, err)
	defer ingress.Close()
	observation := ingress.Process(packet, reader.LinkType(), "fixture", nil)
	require.NotNil(t, observation)
	captured := &data.CapturedPacket{Data: raw, TimestampNs: ci.Timestamp.UnixNano(), CaptureLength: uint32(ci.CaptureLength), OriginalLength: uint32(ci.Length), LinkType: uint32(reader.LinkType()), Metadata: protocolmeta.Enrich(packet, nil, false), Radius: grpcadapter.RADIUSToProto(observation)}
	p, err := New(Config{ListenAddr: ":0", ProcessorID: "event-test", EventQueueSize: 16})
	require.NoError(t, err)
	sink := &collectingSink{}
	require.NoError(t, p.RegisterEventSink(sink, events.KindRADIUS))
	require.NoError(t, p.eventDispatcher.Start(context.Background()))
	p.emitProtocolEvents("hunter", []*data.CapturedPacket{captured})
	require.NoError(t, p.eventDispatcher.Close(context.Background()))
	require.Len(t, sink.events, 1)
	event := sink.events[0].(events.RADIUSEvent)
	require.Equal(t, uint8(1), event.Code)
	require.Equal(t, "request", event.Association)
	require.NotEmpty(t, event.Attributes)
	require.NotEmpty(t, event.Envelope().UID)
}
