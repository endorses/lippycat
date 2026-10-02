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
	mu            sync.Mutex
	tracker       *CallTracker
	events        []string
	startEntered  chan struct{}
	releaseStart  chan struct{}
	firstStart    sync.Once
	firstStartErr error
}

func (o *queryingLifecycleOutput) OnCallStarted(call *CallInfo) error {
	if !o.tracker.IsCallActive(call.CallID) {
		return fmt.Errorf("started call %q is not visible in registry", call.CallID)
	}
	o.mu.Lock()
	o.events = append(o.events, "start:"+call.CallID)
	o.mu.Unlock()
	var startErr error
	if o.startEntered != nil {
		o.firstStart.Do(func() {
			close(o.startEntered)
			<-o.releaseStart
			startErr = o.firstStartErr
		})
	}
	return startErr
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

func TestConcurrentCallLookupWaitsForLifecycleInitialization(t *testing.T) {
	for _, failFirstStart := range []bool{false, true} {
		name := "success"
		if failFirstStart {
			name = "failed_start_is_rolled_back_before_retry"
		}
		t.Run(name, func(t *testing.T) {
			const callID = "initializing"
			output := &queryingLifecycleOutput{
				startEntered: make(chan struct{}),
				releaseStart: make(chan struct{}),
			}
			if failFirstStart {
				output.firstStartErr = fmt.Errorf("injected lifecycle initialization failure")
			}
			tracker := NewCallTrackerWithOutput(DefaultConfig(), output)
			output.tracker = tracker
			var releaseOnce sync.Once
			release := func() { releaseOnce.Do(func() { close(output.releaseStart) }) }
			t.Cleanup(func() {
				release()
				tracker.Shutdown()
			})

			created := make(chan *CallInfo, 1)
			go func() {
				created <- tracker.GetOrCreateCall(callID, layers.LinkTypeEthernet)
			}()
			select {
			case <-output.startEntered:
			case <-time.After(time.Second):
				t.Fatal("lifecycle initialization did not start")
			}

			// Observers must still be able to query the admitted call while they
			// initialize it; only callers asking to use/create it must wait.
			initializing, err := tracker.GetCall(callID)
			require.NoError(t, err)
			require.NotNil(t, initializing)
			lookupEntered := make(chan struct{})
			lookedUp := make(chan *CallInfo, 1)
			go func() {
				close(lookupEntered)
				lookedUp <- tracker.GetOrCreateCall(callID, layers.LinkTypeEthernet)
			}()
			select {
			case <-lookupEntered:
			case <-time.After(time.Second):
				t.Fatal("concurrent lookup did not start")
			}
			select {
			case <-lookedUp:
				t.Fatal("concurrent lookup returned before lifecycle initialization completed")
			case <-time.After(20 * time.Millisecond):
			}

			release()
			var first, second *CallInfo
			select {
			case first = <-created:
			case <-time.After(time.Second):
				t.Fatal("initial creation did not finish")
			}
			select {
			case second = <-lookedUp:
			case <-time.After(time.Second):
				t.Fatal("concurrent lookup did not finish")
			}
			require.NotNil(t, second)
			if failFirstStart {
				require.Nil(t, first)
				require.NotSame(t, initializing, second, "lookup must retry after the failed generation is removed")
			} else {
				require.Same(t, initializing, first)
				require.Same(t, first, second)
			}
			current, err := tracker.GetCall(callID)
			require.NoError(t, err)
			require.Same(t, second, current)
			output.mu.Lock()
			events := append([]string(nil), output.events...)
			output.mu.Unlock()
			if failFirstStart {
				require.Equal(t, []string{"start:initializing", "end:initializing", "start:initializing"}, events)
			} else {
				require.Equal(t, []string{"start:initializing"}, events)
			}
		})
	}
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
	ct := NewCallTrackerWithConfig(cfg)
	t.Cleanup(ct.Shutdown)

	cfg.MaxCalls = 99
	assert.Equal(t, 7, ct.maxCalls)
}

func TestEndpointRegistrationRequiresAdmittedCallAndIsBounded(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxEndpointsPerCall = 2
	cfg.MaxEndpointAssociations = 3
	ct := NewCallTrackerWithConfig(cfg)
	t.Cleanup(ct.Shutdown)

	ct.registerEndpoint("4000", "missing")
	assert.Empty(t, ct.registry.CallIDsForEndpoint("4000"))

	assert.NotNil(t, ct.GetOrCreateCall("first", layers.LinkTypeEthernet))
	assert.NotNil(t, ct.GetOrCreateCall("second", layers.LinkTypeEthernet))
	ct.registerEndpoint("4000", "first")
	ct.registerEndpoint("4002", "first")
	ct.registerEndpoint("4004", "first") // per-call limit
	ct.registerEndpoint("5000", "second")
	ct.registerEndpoint("5002", "second") // global limit

	assert.Len(t, ct.registry.EndpointsForCall("first"), 2)
	assert.Len(t, ct.registry.EndpointsForCall("second"), 1)
	assert.Empty(t, ct.registry.CallIDsForEndpoint("4004"))
	assert.Empty(t, ct.registry.CallIDsForEndpoint("5002"))
}

func createTrackedCall(ct *CallTracker, id string) {
	ct.GetOrCreateCall(id, layers.LinkTypeEthernet)
}
