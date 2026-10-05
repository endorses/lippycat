//go:build hunter || all

package voip

import (
	"testing"
	"time"

	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/require"
)

func TestHunterHandlersBindConfiguredSDPEndpointBudget(t *testing.T) {
	for _, transport := range []string{"UDP", "TCP"} {
		t.Run(transport, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.MaxEndpointsPerCall = 2
			tracker := NewCallTrackerWithConfig(cfg)
			t.Cleanup(tracker.Shutdown)
			buffers := NewBufferManager(time.Minute, 10)
			t.Cleanup(buffers.Close)
			forwarder := &recordingHunterForwarder{}
			if transport == "UDP" {
				handler := NewUDPPacketHandler(tracker, forwarder, buffers)
				t.Cleanup(handler.Close)
			} else {
				handler := NewHunterForwardHandler(tracker, forwarder, buffers)
				t.Cleanup(handler.Close)
			}
			require.Equal(t, cfg.MaxEndpointsPerCall, buffers.sdpEndpointLimit)
			body := "c=IN IP4 192.0.2.1\r\nm=audio 10000 RTP/AVP 0\r\nm=video 11000 RTP/AVP 96\r\n"
			buffers.AddSIPPacket("synthetic-budget", nil, &CallMetadata{SDPBody: body}, "test0", layers.LinkTypeEthernet)
			buffers.mu.RLock()
			buffer := buffers.buffers["synthetic-budget"]
			buffers.mu.RUnlock()
			require.True(t, buffer.IsRTPPort("192.0.2.1:10000"))
			require.True(t, buffer.IsRTPPort("192.0.2.1:10001"))
			require.False(t, buffer.IsRTPPort("192.0.2.1:11000"))
			require.False(t, buffer.IsRTPPort("10000"))
			require.Equal(t, uint64(1), buffers.SDPParseStats().ResourceLimited)
		})
	}
}
