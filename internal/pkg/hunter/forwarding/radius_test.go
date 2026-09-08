//go:build hunter || all

package forwarding

import (
	"context"
	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/pipeline"
	"github.com/endorses/lippycat/internal/pkg/radius"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcapgo"
	"github.com/stretchr/testify/require"
	"os"
	"sync"
	"testing"
	"time"
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

func TestForwardRADIUSIdentityFreeResponse(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	buffer := capture.NewPacketBuffer(ctx, 10)
	defer buffer.Close()
	processor, err := radius.NewCaptureProcessor(radius.CaptureScope{OriginNodeID: "hunter"})
	require.NoError(t, err)
	defer processor.Close()
	predicate, err := radius.CompilePredicate(radius.PredicateSpec{Kind: radius.PredicateUserName, Value: "alice@example.test", FilterID: "user", FilterRevision: 1})
	require.NoError(t, err)
	m := &Manager{config: Config{HunterID: "hunter", BatchSize: 2, BatchTimeout: time.Second}, connCtx: ctx, statsCollector: &flowStats{}, packetBufferProv: testPacketBufferProvider{buffer: buffer}, batchQueue: make(chan *pipeline.PacketBatch, 2), radiusProcessor: processor, applicationFilter: &radiusSourceFilter{predicate: predicate}}
	file, err := os.Open("../../../../testdata/radius/acceptance.pcap")
	require.NoError(t, err)
	defer func() { require.NoError(t, file.Close()) }()
	reader, err := pcapgo.NewReader(file)
	require.NoError(t, err)
	var wg sync.WaitGroup
	wg.Add(1)
	go m.ForwardPackets(&wg)
	for i := 0; i < 2; i++ {
		raw, ci, err := reader.ReadPacketData()
		require.NoError(t, err)
		packet := gopacket.NewPacket(raw, reader.LinkType(), gopacket.Default)
		packet.Metadata().CaptureInfo = ci
		buffer.Send(capture.PacketInfo{Packet: packet, LinkType: reader.LinkType(), Interface: "mirror"})
	}
	select {
	case batch := <-m.batchQueue:
		require.Len(t, batch.Packets, 2)
		require.Equal(t, radius.AssociationUnique, batch.Packets[1].RADIUS.Association.Status)
		require.Len(t, batch.Packets[1].RADIUS.Inherited, 1)
		require.Empty(t, batch.Packets[1].MatchedFilterIDs)
	case <-time.After(3 * time.Second):
		t.Fatal("identity-free response did not pass forwarding gate")
	}
	cancel()
	wg.Wait()
}
