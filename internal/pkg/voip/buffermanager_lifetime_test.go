package voip

import (
	"github.com/endorses/lippycat/internal/pkg/callregistry"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func matchedBufferFixture(t *testing.T) (*BufferManager, *callregistry.Core, callregistry.MediaResolution) {
	t.Helper()
	registry := callregistry.New(callregistry.Config{MaxCalls: 10, MaxEndpointsPerCall: 4, MaxEndpointAssociations: 20})
	t.Cleanup(registry.Close)
	bm := NewBufferManager(time.Second, 10)
	t.Cleanup(bm.Close)
	bm.BindRegistry(registry)
	registry.Upsert(callregistry.Call{CallID: "call"})
	require.True(t, registry.TryAssociateEndpoint("call", "192.0.2.1:10000"))
	bm.MarkCallMatched("call", &CallMetadata{CallID: "call", SDPBody: "v=0\r\nc=IN IP4 192.0.2.1\r\nm=audio 10000 RTP/AVP 0\r\n"}, "eth0", layers.LinkTypeEthernet)
	bm.StoreMatchedFilterIDs("call", []string{"identity"})
	return bm, registry, registry.ResolveMediaEndpoints("192.0.2.1:10000", "192.0.2.2:20000")
}
func ageMatchedBuffer(t *testing.T, bm *BufferManager) {
	t.Helper()
	bm.mu.Lock()
	buffer := bm.buffers["call"]
	buffer.mu.Lock()
	buffer.createdAt = time.Now().Add(-time.Minute)
	buffer.mu.Unlock()
	bm.mu.Unlock()
	bm.cleanupOldBuffers()
	require.Zero(t, bm.GetBufferCount())
}
func TestBufferManagerMatchedMediaSurvivesPacketBufferExpiry(t *testing.T) {
	bm, registry, resolution := matchedBufferFixture(t)
	ageMatchedBuffer(t, bm)
	for i := 0; i < 100; i++ {
		forward, accepted, ids := bm.AddResolvedRTPPacket(resolution, "192.0.2.1:10000", "192.0.2.2:20000", nil)
		require.True(t, forward)
		require.True(t, accepted)
		require.Equal(t, []string{"identity"}, ids)
	}
	require.Zero(t, bm.GetBufferCount(), "matched media must not recreate or extend packet retention")
	// Current authoritative late SDP endpoints work without another packet buffer.
	require.True(t, registry.TryAssociateEndpoint("call", "192.0.2.1:11000"))
	newer := registry.ResolveMediaEndpoints("192.0.2.1:11000", "192.0.2.2:21000")
	forward, accepted, _ := bm.AddResolvedRTPPacket(newer, "192.0.2.1:11000", "192.0.2.2:21000", nil)
	require.True(t, forward)
	require.True(t, accepted)
}
func TestBufferManagerMatchedMediaRevalidatesAuthority(t *testing.T) {
	for _, scenario := range []string{"endpoint removed", "ambiguous", "call removed", "reused matched", "TTL expired"} {
		t.Run(scenario, func(t *testing.T) {
			bm, registry, old := matchedBufferFixture(t)
			ageMatchedBuffer(t, bm)
			switch scenario {
			case "endpoint removed":
				registry.DissociateEndpoints("call")
			case "ambiguous":
				registry.Upsert(callregistry.Call{CallID: "other"})
				registry.TryAssociateEndpoint("other", "192.0.2.1:10000")
			case "call removed":
				registry.Remove("call", callregistry.EndCompleted)
			case "reused matched":
				registry.Remove("call", callregistry.EndCompleted)
				registry.Upsert(callregistry.Call{CallID: "call"})
				registry.TryAssociateEndpoint("call", "192.0.2.1:10000")
				require.Empty(t, bm.MatchedFilterIDs("call"))
				require.False(t, bm.IsCallMatched("call"))
				bm.StoreMatchedFilterIDs("call", []string{"new-identity"})
				bm.MarkCallMatched("call", &CallMetadata{CallID: "call"}, "eth0", layers.LinkTypeEthernet)
			case "TTL expired":
				bm.mu.Lock()
				bm.matchedCalls["call"] = time.Now().Add(-bm.matchedTTL - time.Second)
				bm.mu.Unlock()
			}
			forward, accepted, ids := bm.AddResolvedRTPPacket(old, "192.0.2.1:10000", "192.0.2.2:20000", nil)
			require.False(t, forward)
			require.False(t, accepted)
			require.Empty(t, ids)
			require.Empty(t, bm.MatchedFilterIDsForResolution(old, "192.0.2.1:10000", "192.0.2.2:20000"))
			if scenario == "reused matched" {
				current := registry.ResolveMediaEndpoints("192.0.2.1:10000", "192.0.2.2:20000")
				forward, accepted, ids = bm.AddResolvedRTPPacket(current, "192.0.2.1:10000", "192.0.2.2:20000", nil)
				require.True(t, forward)
				require.True(t, accepted)
				require.Equal(t, []string{"new-identity"}, ids)
			}
		})
	}
}
func TestBufferManagerResolvedPendingMediaStillBuffers(t *testing.T) {
	bm, registry, _ := matchedBufferFixture(t)
	registry.Upsert(callregistry.Call{CallID: "pending"})
	registry.TryAssociateEndpoint("pending", "192.0.2.3:30000")
	bm.AddSIPPacket("pending", nil, &CallMetadata{CallID: "pending", SDPBody: "v=0\r\nc=IN IP4 192.0.2.3\r\nm=audio 30000 RTP/AVP 0\r\n"}, "eth0", layers.LinkTypeEthernet)
	resolution := registry.ResolveMediaEndpoints("192.0.2.3:30000", "192.0.2.4:40000")
	forward, accepted, ids := bm.AddResolvedRTPPacket(resolution, "192.0.2.3:30000", "192.0.2.4:40000", nil)
	require.False(t, forward)
	require.True(t, accepted)
	require.Empty(t, ids)
	bm.mu.RLock()
	count := bm.buffers["pending"].GetPacketCount()
	bm.mu.RUnlock()
	require.Equal(t, 1, count)
}
