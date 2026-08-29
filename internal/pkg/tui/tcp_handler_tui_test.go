//go:build tui || all

package tui

import (
	"fmt"
	"testing"
	"time"

	sharedsip "github.com/endorses/lippycat/internal/pkg/sip"
	"github.com/google/gopacket"
	"github.com/stretchr/testify/require"
)

func TestTUISIPHandlerSharedFlowPreservesLegacyAndParsedSemantics(t *testing.T) {
	at := time.Date(2026, time.August, 29, 14, 0, 0, 123, time.UTC)
	sdp := "v=0\r\nc=IN IP4 203.0.113.20\r\nm=audio 20000 RTP/AVP 0\r\n"
	message := []byte(fmt.Sprintf("INVITE sip:bob@example.test SIP/2.0\r\nCall-ID: tui-shared\r\nCSeq: 1 INVITE\r\nFrom: <sip:alice@example.test>\r\nTo: <sip:bob@example.test>\r\nContent-Type: application/sdp\r\nContent-Length: %d\r\n\r\n%s", len(sdp), sdp))
	opts := sharedsip.OptionsForEndpoints(at, "192.0.2.10:5060", "198.51.100.20:5060")
	event, err := sharedsip.Parse(message, opts)
	require.NoError(t, err)
	require.Equal(t, []uint16{20000}, extractMediaPortsFromSIP(event.Body))

	legacyTracker := NewCallTracker()
	legacy := NewTUISIPHandler(legacyTracker, nil)
	t.Cleanup(legacy.Close)
	require.True(t, legacy.HandleSIPMessageAt(message, event.CallID, "192.0.2.10:5060", "198.51.100.20:5060", gopacket.Flow{}, gopacket.Flow{}, at))

	parsedTracker := NewCallTracker()
	parsed := NewTUISIPHandler(parsedTracker, nil)
	t.Cleanup(parsed.Close)
	require.True(t, parsed.HandleParsedSIPMessage(message, event, "192.0.2.10:5060", "198.51.100.20:5060", gopacket.Flow{}, gopacket.Flow{}))

	for _, tracker := range []*CallTracker{legacyTracker, parsedTracker} {
		require.Contains(t, tracker.GetEndpointsForCall(event.CallID), "192.0.2.10:20000")
		require.Equal(t, event.CallID, tracker.GetCallIDForRTPPacket("x", "y", "192.0.2.10", "20000"))
		from, to := tracker.GetCallPartyInfo(event.CallID)
		require.Equal(t, event.From, from)
		require.Equal(t, event.To, to)
	}
}

func TestTUISIPHandlerCloseStopsAdmission(t *testing.T) {
	handler := NewTUISIPHandler(NewCallTracker(), nil)
	handler.Close()
	message := []byte("OPTIONS sip:bob@example.test SIP/2.0\r\nCall-ID: closed\r\nCSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\n")
	require.False(t, handler.HandleSIPMessageAt(message, "closed", "192.0.2.1:5060", "198.51.100.2:5060", gopacket.Flow{}, gopacket.Flow{}, time.Unix(1, 0)))
}
