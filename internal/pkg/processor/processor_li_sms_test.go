//go:build (processor || tap || all) && li

package processor

import (
	"testing"

	"github.com/endorses/lippycat/internal/pkg/sms"
	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/stretchr/testify/require"
)

func TestLICorrelationSnapshotDoesNotRetainPresentationSMS(t *testing.T) {
	p := &Processor{}
	message := &sms.Message{Status: sms.StatusDecoded, Text: "presentation-only content"}
	packet := &types.PacketDisplay{RawData: []byte("raw SIP"), VoIPData: &types.VoIPMetadata{CallID: "sms", RawSIP: []byte("framed SIP"), SMS: message}}
	snapshot, ok := p.snapshotLICorrelationPacket(packet, nil)
	require.True(t, ok)
	require.Nil(t, snapshot.packet.VoIPData.SMS)
	require.Same(t, message, packet.VoIPData.SMS)
	require.Equal(t, packet.VoIPData.RawSIP, snapshot.packet.VoIPData.RawSIP)
	packet.VoIPData.RawSIP[0] = 'X'
	require.NotEqual(t, packet.VoIPData.RawSIP, snapshot.packet.VoIPData.RawSIP)
}
