package voip

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

type queryingLifecycleOutput struct {
	mu           sync.Mutex
	tracker      *CallTracker
	events       []string
	startEntered chan struct{}
	releaseStart chan struct{}
}

func (o *queryingLifecycleOutput) OnCallStarted(call *CallInfo) error {
	if !o.tracker.IsCallActive(call.CallID) {
		return fmt.Errorf("started call %q is not visible in registry", call.CallID)
	}
	o.mu.Lock()
	o.events = append(o.events, "start:"+call.CallID)
	o.mu.Unlock()
	if o.startEntered != nil {
		close(o.startEntered)
		<-o.releaseStart
	}
	return nil
}

func (o *queryingLifecycleOutput) OnCallEnded(call *CallInfo) error {
	o.mu.Lock()
	o.events = append(o.events, "end:"+call.CallID)
	o.mu.Unlock()
	return nil
}

func (o *queryingLifecycleOutput) OpenSession(string, layers.LinkType) error { return nil }
func (o *queryingLifecycleOutput) WritePacket(string, gopacket.Packet, PacketType) error {
	return nil
}
func (o *queryingLifecycleOutput) CloseSession(string) error { return nil }
func (o *queryingLifecycleOutput) Shutdown() error           { return nil }

func TestLifecycleObserverRunsAfterAdmissionWhenOutputDisabled(t *testing.T) {
	cfg := DefaultConfig()
	cfg.WriteVoIP = false
	output := &queryingLifecycleOutput{}
	tracker := NewCallTrackerWithOutput(cfg, output)
	output.tracker = tracker

	call := tracker.GetOrCreateCall("observed", layers.LinkTypeEthernet)
	require.NotNil(t, call)
	tracker.Shutdown()

	output.mu.Lock()
	defer output.mu.Unlock()
	require.Equal(t, []string{"start:observed", "end:observed"}, output.events)
}

func TestLifecycleStartPrecedesConcurrentShutdownEnd(t *testing.T) {
	cfg := DefaultConfig()
	output := &queryingLifecycleOutput{
		startEntered: make(chan struct{}),
		releaseStart: make(chan struct{}),
	}
	tracker := NewCallTrackerWithOutput(cfg, output)
	output.tracker = tracker

	created := make(chan *CallInfo, 1)
	go func() {
		created <- tracker.GetOrCreateCall("concurrent", layers.LinkTypeEthernet)
	}()
	<-output.startEntered

	shutdownDone := make(chan struct{})
	go func() {
		tracker.Shutdown()
		close(shutdownDone)
	}()
	require.Eventually(t, func() bool {
		return tracker.shuttingDown.Load() != 0
	}, time.Second, time.Millisecond)

	select {
	case <-shutdownDone:
		t.Fatal("shutdown delivered the end event before the start callback completed")
	case <-time.After(20 * time.Millisecond):
	}
	close(output.releaseStart)
	require.NotNil(t, <-created)
	<-shutdownDone

	output.mu.Lock()
	defer output.mu.Unlock()
	require.Equal(t, []string{"start:concurrent", "end:concurrent"}, output.events)
}

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
