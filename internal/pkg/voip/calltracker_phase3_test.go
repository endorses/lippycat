package voip

import (
	"time"

	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
	"testing"
)

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
