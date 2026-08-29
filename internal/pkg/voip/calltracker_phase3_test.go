package voip

import (
	"sync"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
)

type recordingCallOutput struct {
	mu             sync.Mutex
	opened, closed []string
}

func (r *recordingCallOutput) OpenSession(id string, _ layers.LinkType) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.opened = append(r.opened, id)
	return nil
}
func (r *recordingCallOutput) WritePacket(string, gopacket.Packet, PacketType) error { return nil }
func (r *recordingCallOutput) CloseSession(id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closed = append(r.closed, id)
	return nil
}
func (r *recordingCallOutput) Shutdown() error { return nil }

func TestPinnedCallSurvivesCapacityPressure(t *testing.T) {
	ct := NewCallTrackerWithCapacity(2)
	t.Cleanup(ct.Shutdown)
	ct.PinCall("pinned")
	createTrackedCall(ct, "pinned")
	createTrackedCall(ct, "ordinary")
	createTrackedCall(ct, "new")
	ct.mu.RLock()
	_, pinned := ct.callMap["pinned"]
	_, ordinary := ct.callMap["ordinary"]
	ct.mu.RUnlock()
	assert.True(t, pinned)
	assert.False(t, ordinary)
	ct.UnpinCall("pinned")
	createTrackedCall(ct, "later")
	ct.mu.RLock()
	_, pinned = ct.callMap["pinned"]
	ct.mu.RUnlock()
	assert.False(t, pinned)
}

func TestRTPOnlyCallAtomicRecencyProtectsItFromEviction(t *testing.T) {
	ct := NewCallTrackerWithCapacity(2)
	t.Cleanup(ct.Shutdown)
	ct.getOrCreateCall("rtp-recent", layers.LinkTypeEthernet)
	time.Sleep(time.Millisecond)
	ct.getOrCreateCall("ordinary", layers.LinkTypeEthernet)

	// A later RTP lookup refreshes recency without moving the locked LRU list.
	time.Sleep(time.Millisecond)
	ct.getOrCreateCall("rtp-recent", layers.LinkTypeEthernet)
	ct.getOrCreateCall("new", layers.LinkTypeEthernet)

	ct.mu.RLock()
	_, recentExists := ct.callMap["rtp-recent"]
	_, ordinaryExists := ct.callMap["ordinary"]
	ct.mu.RUnlock()
	assert.True(t, recentExists)
	assert.False(t, ordinaryExists)
}

func TestPinnedCallsEnforceHardCapacity(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxCalls = 1
	cfg.WriteVoIP = true
	output := &recordingCallOutput{}
	ct := NewCallTrackerWithOutput(cfg, output)
	t.Cleanup(ct.Shutdown)
	ct.PinCall("pinned")
	assert.NotNil(t, ct.GetOrCreateCall("pinned", layers.LinkTypeEthernet))

	assert.Nil(t, ct.GetOrCreateCall("rejected", layers.LinkTypeEthernet))
	ct.mu.RLock()
	defer ct.mu.RUnlock()
	assert.Len(t, ct.callMap, 1)
	assert.Contains(t, ct.callMap, "pinned")
	assert.Equal(t, []string{"pinned"}, output.opened, "rejected calls must not allocate output resources")
}

func TestCallTrackerCopiesConfig(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxCalls = 7
	cfg.PluginPaths = []string{"original"}
	ct := NewCallTrackerWithConfig(cfg)
	t.Cleanup(ct.Shutdown)

	cfg.MaxCalls = 99
	cfg.PluginPaths[0] = "changed"
	assert.Equal(t, 7, ct.maxCalls)
	assert.Equal(t, []string{"original"}, ct.config.PluginPaths)
}

func TestEndpointRegistrationRequiresAdmittedCallAndIsBounded(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxEndpointsPerCall = 2
	cfg.MaxEndpointAssociations = 3
	ct := NewCallTrackerWithConfig(cfg)
	t.Cleanup(ct.Shutdown)

	ct.registerEndpoint("4000", "missing")
	assert.Empty(t, ct.portToCallID)

	assert.NotNil(t, ct.GetOrCreateCall("first", layers.LinkTypeEthernet))
	assert.NotNil(t, ct.GetOrCreateCall("second", layers.LinkTypeEthernet))
	ct.registerEndpoint("4000", "first")
	ct.registerEndpoint("4002", "first")
	ct.registerEndpoint("4004", "first") // per-call limit
	ct.registerEndpoint("5000", "second")
	ct.registerEndpoint("5002", "second") // global limit

	ct.mu.RLock()
	defer ct.mu.RUnlock()
	assert.Len(t, ct.portToCallID, 3)
	assert.NotContains(t, ct.portToCallID, "4004")
	assert.NotContains(t, ct.portToCallID, "5002")
}

func createTrackedCall(ct *CallTracker, id string) {
	ct.mu.Lock()
	defer ct.mu.Unlock()
	if ct.lruList.Len() >= ct.maxCalls {
		for e := ct.lruList.Back(); e != nil; e = e.Prev() {
			old := e.Value.(string)
			if ct.pins[old] == 0 {
				delete(ct.callMap, old)
				delete(ct.lruIndex, old)
				ct.lruList.Remove(e)
				break
			}
		}
	}
	c := &CallInfo{CallID: id, LinkType: layers.LinkTypeEthernet}
	ct.callMap[id] = c
	ct.lruIndex[id] = ct.lruList.PushFront(id)
}
