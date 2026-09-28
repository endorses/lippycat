package eventanalysis

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/endorses/lippycat/internal/pkg/protocolmeta"
	"github.com/endorses/lippycat/internal/pkg/testutil/radiusfixture"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcapgo"
	"github.com/stretchr/testify/require"
)

func TestGenericCapturedRADIUSFallback(t *testing.T) {
	f, err := os.Open(filepath.Join(radiusfixture.Write(t), "acceptance.pcap"))
	require.NoError(t, err)
	defer func() { require.NoError(t, f.Close()) }()
	reader, err := pcapgo.NewReader(f)
	require.NoError(t, err)
	r, d, sink := testRuntime(t, 32)
	defer r.Close()
	for i := 0; i < 5; i++ {
		raw, ci, err := reader.ReadPacketData()
		require.NoError(t, err)
		packet := gopacket.NewPacket(raw, reader.LinkType(), gopacket.Default)
		packet.Metadata().CaptureInfo = ci
		require.NoError(t, r.ObserveCaptured(Source{NodeID: "node", CaptureSource: "pcap"}, []*data.CapturedPacket{{
			Data: raw, TimestampNs: ci.Timestamp.UnixNano(), LinkType: uint32(reader.LinkType()),
			CaptureLength: uint32(ci.CaptureLength), OriginalLength: uint32(ci.Length), Metadata: protocolmeta.Enrich(packet, nil, false),
		}}))
	}
	r.EOF()
	require.NoError(t, d.Close(context.Background()))
	var radiusEvents int
	for _, event := range sink.events {
		if event.Kind() == events.KindRADIUS {
			radiusEvents++
		}
	}
	// The first four records use the default port, while the fifth requires
	// explicit configured-port provenance from the ingress owner.
	require.Equal(t, 4, radiusEvents)
}
