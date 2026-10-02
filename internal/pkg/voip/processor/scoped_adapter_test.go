package processor

import (
	"github.com/endorses/lippycat/internal/pkg/callregistry"
	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/mediaadmission"
	"github.com/stretchr/testify/require"
	"net"
	"testing"
	"time"
)

func scopedFixture(t *testing.T, grace time.Duration) (*SourceAdapter, *Processor, *Processor) {
	t.Helper()
	cfg := mediaadmission.DefaultConfig()
	cfg.InterfaceDomains = map[string]mediaadmission.DomainID{"left": 0, "right": 1}
	left, right := New(DefaultConfig()), New(DefaultConfig())
	adapter, err := NewScopedSourceAdapter(cfg, map[mediaadmission.DomainID]*SourceAdapter{0: NewSourceAdapter(left), 1: NewSourceAdapter(right)}, grace)
	require.NoError(t, err)
	t.Cleanup(adapter.Close)
	return adapter, left, right
}
func TestScopedMediaAndCacheLifetime(t *testing.T) {
	adapter, left, right := scopedFixture(t, time.Hour)
	left.AssociateEndpoint("same-call", "192.0.2.2:10000")
	packet := createRTPPacket(t, net.ParseIP("192.0.2.1"), net.ParseIP("192.0.2.2"), 20000, 10000)
	selected := adapter.ProcessPacketInfo(capture.PacketInfo{Packet: packet, Interface: "left"})
	require.Equal(t, callregistry.MediaResolved, selected.GetMediaResolution().Status)
	require.Equal(t, "same-call", selected.GetCallID())
	require.Equal(t, callregistry.MediaUnresolved, adapter.ProcessPacketInfo(capture.PacketInfo{Packet: packet, Interface: "right"}).GetMediaResolution().Status)
	oldLife := selected.GetCallLifetime()
	oldKey := adapter.FilterCacheKeyForLifetime("same-call", "left", oldLife)
	require.NotEmpty(t, oldKey)
	require.Empty(t, adapter.FilterCacheKeyForLifetime("same-call", "right", oldLife))
	right.AssociateEndpoint("same-call", "192.0.2.2:10000")
	other := adapter.ProcessPacketInfo(capture.PacketInfo{Packet: packet, Interface: "right"})
	require.NotEqual(t, oldKey, adapter.FilterCacheKeyForLifetime("same-call", "right", other.GetCallLifetime()))
	left.FinalizeCallLifetime("same-call", oldLife)
	left.AssociateEndpoint("same-call", "192.0.2.2:10000")
	require.Empty(t, adapter.FilterCacheKeyForLifetime("same-call", "left", oldLife))
	// A delayed terminal packet must not schedule completion for the new life.
	left.CompleteCallLifetime("same-call", oldLife)
	require.Empty(t, adapter.scoped.timers)
	adapter.CleanupCallPorts("same-call")
	require.Len(t, left.CallIDsForEndpoint("192.0.2.2:10000"), 1)
	require.Len(t, right.CallIDsForEndpoint("192.0.2.2:10000"), 1)
}
func TestScopedCompletionGraceAndReusedLifetime(t *testing.T) {
	adapter, left, right := scopedFixture(t, 30*time.Millisecond)
	left.AssociateEndpoint("same-call", "192.0.2.2:10000")
	right.AssociateEndpoint("same-call", "192.0.2.2:10000")
	old, _ := left.Call("same-call")
	left.CompleteCallLifetime("same-call", old.Lifetime)
	require.Len(t, left.CallIDsForEndpoint("192.0.2.2:10000"), 1)
	require.Eventually(t, func() bool { _, ok := left.Call("same-call"); return !ok }, time.Second, time.Millisecond)
	_, ok := right.Call("same-call")
	require.True(t, ok)
	left.AssociateEndpoint("same-call", "192.0.2.2:10000")
	first, _ := left.Call("same-call")
	left.CompleteCallLifetime("same-call", first.Lifetime)
	left.FinalizeCallLifetime("same-call", first.Lifetime)
	left.AssociateEndpoint("same-call", "192.0.2.2:10000")
	require.Eventually(t, func() bool {
		adapter.scoped.mu.Lock()
		defer adapter.scoped.mu.Unlock()
		return len(adapter.scoped.timers) == 0
	}, time.Second, time.Millisecond)
	current, ok := left.Call("same-call")
	require.True(t, ok)
	require.NotEqual(t, first.Lifetime, current.Lifetime)
}
