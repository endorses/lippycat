package processor

import (
	"strings"
	"testing"

	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/pipeline"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/require"
)

type recordingMetadataObserver struct {
	observed, selected []pipeline.SIPResult
}

func (o *recordingMetadataObserver) ObserveValidated(r pipeline.SIPResult) error {
	o.observed = append(o.observed, r)
	return nil
}
func (o *recordingMetadataObserver) Selected(r pipeline.SIPResult) error {
	o.selected = append(o.selected, r)
	return nil
}

func TestLocalAdmissionObservesValidatedUnmatchedSIPWithProvenance(t *testing.T) {
	filter := &countingFilter{}
	proc := newFilteredProcessor(filter, true)
	defer proc.Close()
	observer := &recordingMetadataObserver{}
	require.NoError(t, proc.SetMetadataObserver(observer))
	packet := sipInvitePacket(t, "waiting-for-match")
	result := proc.ProcessPacketInfo(capture.PacketInfo{Packet: packet, Interface: "media-net", LinkType: layers.LinkTypeEthernet})
	require.NotNil(t, result)
	require.Len(t, observer.observed, 1)
	require.Empty(t, observer.selected)
	require.Equal(t, "media-net", observer.observed[0].Packet.Source.InterfaceName)
	require.Equal(t, pipeline.SourceLiveCapture, observer.observed[0].Packet.Source.Kind)
	require.Zero(t, proc.ActiveCallCount())
	filter.matched = true
	require.NotNil(t, proc.ProcessPacketInfo(capture.PacketInfo{Packet: packet, Interface: "media-net", LinkType: layers.LinkTypeEthernet}))
	require.Len(t, observer.selected, 1)
	_, exists := proc.CallRegistry().Call("waiting-for-match")
	require.True(t, exists)
	// Invalid identity never reaches metadata retention, even when selected.
	invalid := sipInvitePacket(t, strings.Repeat("x", 1025))
	require.Nil(t, proc.ProcessPacketInfo(capture.PacketInfo{Packet: invalid, Interface: "media-net", LinkType: layers.LinkTypeEthernet}))
	require.Len(t, observer.observed, 2)
}
