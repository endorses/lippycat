package capture

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// Synthetic SIP/RTP sources keep this ordering regression test reproducible
// without relying on private captures on a developer's machine.
func TestOfflineFlowIntegration(t *testing.T) {
	base := time.Unix(100, 0).UTC()
	sip := writeTimestampedTestPCAPWithPayload(t, []timestampedPayload{
		{base.Add(time.Second), "INVITE sip:bob@example.com SIP/2.0\r\n\r\n"},
		{base.Add(4 * time.Second), "SIP/2.0 200 OK\r\n\r\n"},
		{base.Add(6 * time.Second), "BYE sip:bob@example.com SIP/2.0\r\n\r\n"},
	})
	rtp := writeTimestampedTestPCAPWithPayload(t, []timestampedPayload{
		{base.Add(2 * time.Second), "\x80\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x01audio1"},
		{base.Add(3 * time.Second), "\x80\x00\x00\x02\x00\x00\x00\x02\x00\x00\x00\x01audio2"},
		{base.Add(5 * time.Second), "\x80\x00\x00\x03\x00\x00\x00\x03\x00\x00\x00\x01audio3"},
	})
	var got []PacketInfo
	err := RunOfflineOrderedContext(context.Background(), offlineTestDevices(t, rtp, sip), "", func(ch <-chan PacketInfo) {
		for packet := range ch {
			got = append(got, packet)
		}
	})
	require.NoError(t, err)
	require.Len(t, got, 6)
	for i, packet := range got {
		require.Equal(t, base.Add(time.Duration(i+1)*time.Second), packet.Packet.Metadata().Timestamp)
	}
	require.Equal(t, []string{sip, rtp, rtp, sip, rtp, sip}, []string{
		got[0].SourcePath, got[1].SourcePath, got[2].SourcePath,
		got[3].SourcePath, got[4].SourcePath, got[5].SourcePath,
	})
}
