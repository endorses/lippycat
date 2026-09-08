package source

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/radius"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/stretchr/testify/require"
)

type radiusSourceFilter struct{ predicate *radius.Predicate }

func (*radiusSourceFilter) MatchPacket(gopacket.Packet) bool                    { return false }
func (*radiusSourceFilter) MatchPacketWithIDs(gopacket.Packet) (bool, []string) { return false, nil }
func (*radiusSourceFilter) MatchPacketLevelWithIDs(gopacket.Packet) (bool, []string) {
	return false, nil
}
func (f *radiusSourceFilter) MatchRADIUSObservation(o *radius.Observation) (bool, []string, []radius.AttributionReference) {
	ref, ok, err := f.predicate.Reference(o)
	if err != nil || !ok {
		return false, nil, nil
	}
	return true, []string{"user"}, []radius.AttributionReference{ref}
}
func (f *radiusSourceFilter) RADIUSEvidenceCurrent(r radius.AttributionReference) bool {
	return f.predicate.CurrentReference(r)
}

func TestLocalRADIUSSelectionBeforeUnmatchedGate(t *testing.T) {
	file, err := os.Open("../../../../testdata/radius/acceptance.pcap")
	require.NoError(t, err)
	defer func() { require.NoError(t, file.Close()) }()
	reader, err := pcapgo.NewReader(file)
	require.NoError(t, err)
	var packets []capture.PacketInfo
	for i := 0; i < 2; i++ {
		raw, ci, err := reader.ReadPacketData()
		require.NoError(t, err)
		packet := gopacket.NewPacket(raw, reader.LinkType(), gopacket.Default)
		packet.Metadata().CaptureInfo = ci
		packets = append(packets, capture.PacketInfo{Packet: packet, LinkType: reader.LinkType(), Interface: "mirror0"})
	}
	predicate, err := radius.CompilePredicate(radius.PredicateSpec{Kind: radius.PredicateUserName, Value: "alice@example.test", FilterID: "user", FilterRevision: 1})
	require.NoError(t, err)
	for _, competitor := range []bool{false, true} {
		name := "unique"
		if competitor {
			name = "unmatched_competitor"
		}
		t.Run(name, func(t *testing.T) {
			s := NewLocalSource(DefaultLocalSourceConfig())
			defer s.radiusProcessor.Close()
			s.ctx = context.Background()
			s.SetApplicationFilter(&radiusSourceFilter{predicate: predicate})
			require.True(t, s.SupportsRADIUS())
			input := make(chan capture.PacketInfo, 3)
			input <- packets[0]
			if competitor {
				raw := append([]byte(nil), packets[0].Packet.Data()...)
				// Ethernet + IPv4 + UDP, then Authenticator and the first User-Name AVP.
				raw[14+20+8+4] ^= 1
				raw[14+20+8+20+2] = 'b'
				packet := gopacket.NewPacket(raw, layers.LinkTypeEthernet, gopacket.Default)
				packet.Metadata().CaptureInfo = packets[0].Packet.Metadata().CaptureInfo
				input <- capture.PacketInfo{Packet: packet, LinkType: layers.LinkTypeEthernet, Interface: "mirror0"}
			}
			input <- packets[1]
			close(input)
			s.batchingWorker(input)
			batch := <-s.Batches()
			if competitor {
				require.Len(t, batch.Envelopes, 1)
				return
			}
			require.Len(t, batch.Envelopes, 2)
			request, response := batch.Envelopes[0], batch.Envelopes[1]
			require.Equal(t, radius.AssociationUnique, response.RADIUS.Association.Status)
			require.Len(t, response.RADIUS.Inherited, 1)
			require.Equal(t, request.RADIUS.Association.RequestInstanceID, response.RADIUS.Association.RequestInstanceID)
			require.Equal(t, packets[1].Packet.Data(), response.Data)
			require.True(t, packets[1].Packet.Metadata().Timestamp.Equal(response.CaptureTime))
			require.Empty(t, response.MatchedFilterIDs, "RADIUS references must never enter generic LI IDs")
		})
	}
}

func TestRADIUSCaptureBoundaryRejectsQueuedOldRequest(t *testing.T) {
	processor, err := radius.NewCaptureProcessor(radius.CaptureScope{OriginNodeID: "tap"})
	require.NoError(t, err)
	defer processor.Close()
	file, err := os.Open("../../../../testdata/radius/acceptance.pcap")
	require.NoError(t, err)
	defer func() { require.NoError(t, file.Close()) }()
	reader, err := pcapgo.NewReader(file)
	require.NoError(t, err)
	var packets []gopacket.Packet
	for i := 0; i < 2; i++ {
		raw, ci, err := reader.ReadPacketData()
		require.NoError(t, err)
		packet := gopacket.NewPacket(raw, reader.LinkType(), gopacket.Default)
		packet.Metadata().CaptureInfo = ci
		packets = append(packets, packet)
	}
	request := processor.Process(packets[0], reader.LinkType(), "mirror", nil)
	require.Equal(t, radius.AssociationRequest, request.Association.Status)
	boundary := packets[0].Metadata().Timestamp.Add(time.Millisecond)
	require.NoError(t, processor.AdvanceBoundary(boundary))
	old := processor.Process(packets[0], reader.LinkType(), "mirror", nil)
	require.Equal(t, radius.AssociationMissing, old.Association.Status)
	response := processor.Process(packets[1], reader.LinkType(), "mirror", nil)
	require.Equal(t, radius.AssociationMissing, response.Association.Status)
	require.NotEqual(t, request.Scope.Epoch, response.Scope.Epoch)
	require.NoError(t, processor.AdvanceBoundary(boundary))
	next := processor.Process(packets[1], reader.LinkType(), "mirror", nil)
	require.Equal(t, response.Scope.Epoch, next.Scope.Epoch)
}
