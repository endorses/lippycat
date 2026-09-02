//go:build processor || tap || all

package processor

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type recordingPortCleaner struct {
	mu      sync.Mutex
	callIDs []string
}

func (c *recordingPortCleaner) CleanupCallPorts(callID string) {
	c.mu.Lock()
	c.callIDs = append(c.callIDs, callID)
	c.mu.Unlock()
}

func (c *recordingPortCleaner) calls() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.callIDs...)
}

func newPhase8Manager(t *testing.T, mutate func(*PcapWriterConfig)) *PcapWriterManager {
	t.Helper()
	config := &PcapWriterConfig{
		Enabled:      true,
		OutputDir:    t.TempDir(),
		FilePattern:  "{callid}.pcap",
		SyncInterval: time.Hour,
	}
	if mutate != nil {
		mutate(config)
	}
	manager, err := NewPcapWriterManager(config)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, manager.Close()) })
	return manager
}

func TestPhase8ManagerWriteAndFinalizeAreRaceSafe(t *testing.T) {
	manager := newPhase8Manager(t, nil)
	const callID = "concurrent-finalize"

	start := make(chan struct{})
	var writes sync.WaitGroup
	var unexpected atomic.Pointer[error]
	for range 8 {
		writes.Add(1)
		go func() {
			defer writes.Done()
			<-start
			for range 100 {
				err := manager.WritePacket(callID, "alice", "bob", time.Now(), []byte("packet"), layers.LinkTypeEthernet, false)
				if err != nil && !IsCallFinalized(err) {
					unexpected.CompareAndSwap(nil, &err)
					return
				}
			}
		}()
	}
	close(start)
	result, err := manager.FinalizeCall(callID, CallFinalizationProtocolComplete)
	require.NoError(t, err)
	assert.True(t, result.Finalized)
	writes.Wait()
	if got := unexpected.Load(); got != nil {
		require.NoError(t, *got)
	}
	assert.True(t, manager.IsFinalized(callID))
	err = manager.WritePacket(callID, "alice", "bob", time.Now(), []byte("late"), layers.LinkTypeEthernet, false)
	assert.True(t, IsCallFinalized(err))
}

func TestPhase8FinalizeAndWriterCloseAreIdempotent(t *testing.T) {
	var completed atomic.Int32
	manager := newPhase8Manager(t, func(config *PcapWriterConfig) {
		config.OnCallComplete = func(CallMetadata) { completed.Add(1) }
	})
	writer, err := manager.GetOrCreateWriter("idempotent", "alice", "bob")
	require.NoError(t, err)

	var wg sync.WaitGroup
	for range 12 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, finalizeErr := manager.FinalizeCall("idempotent", CallFinalizationProtocolComplete)
			assert.NoError(t, finalizeErr)
			assert.NoError(t, writer.CloseCall())
			assert.NoError(t, writer.Close())
		}()
	}
	wg.Wait()
	assert.Equal(t, int32(1), completed.Load())
	assert.Error(t, writer.WriteSIPPacket(time.Now(), []byte("after-close"), layers.LinkTypeEthernet))
}

func TestPhase8ManagedWriterCloseCallUsesManagerLifecycle(t *testing.T) {
	var completed atomic.Int32
	manager := newPhase8Manager(t, func(config *PcapWriterConfig) {
		config.OnCallComplete = func(CallMetadata) { completed.Add(1) }
	})
	cleaner := &recordingPortCleaner{}
	manager.SetBeforeFinalize(func(callID string, _ CallFinalizationReason) {
		cleaner.CleanupCallPorts(callID)
	})

	writer, err := manager.GetOrCreateWriter("managed-close", "alice", "bob")
	require.NoError(t, err)
	require.NoError(t, writer.CloseCall())

	assert.True(t, manager.IsFinalized("managed-close"))
	assert.Equal(t, []string{"managed-close"}, cleaner.calls())
	assert.Equal(t, int32(1), completed.Load())
	err = manager.WritePacket("managed-close", "alice", "bob", time.Now(), []byte("late"), layers.LinkTypeEthernet, false)
	assert.True(t, IsCallFinalized(err))
}

func TestPhase8RotationCallbackPrecedesCompletion(t *testing.T) {
	rotationStarted := make(chan struct{})
	releaseRotation := make(chan struct{})
	var once sync.Once
	var mu sync.Mutex
	var events []string
	manager := newPhase8Manager(t, func(config *PcapWriterConfig) {
		config.MaxFileSize = 1
		config.OnFileClose = func(string) {
			mu.Lock()
			events = append(events, "file")
			mu.Unlock()
			once.Do(func() {
				close(rotationStarted)
				<-releaseRotation
			})
		}
		config.OnCallComplete = func(CallMetadata) {
			mu.Lock()
			events = append(events, "complete")
			mu.Unlock()
		}
	})
	require.NoError(t, manager.WritePacket("ordered", "alice", "bob", time.Now(), []byte{1}, layers.LinkTypeEthernet, false))

	writeDone := make(chan error, 1)
	go func() {
		writeDone <- manager.WritePacket("ordered", "alice", "bob", time.Now(), []byte{2}, layers.LinkTypeEthernet, false)
	}()
	<-rotationStarted
	finalizeDone := make(chan error, 1)
	go func() {
		_, err := manager.FinalizeCall("ordered", CallFinalizationProtocolComplete)
		finalizeDone <- err
	}()

	select {
	case err := <-finalizeDone:
		require.NoError(t, err)
		t.Fatal("finalization overtook the pending rotation callback")
	case <-time.After(20 * time.Millisecond):
	}
	close(releaseRotation)
	require.NoError(t, <-writeDone)
	require.NoError(t, <-finalizeDone)

	mu.Lock()
	assert.Equal(t, []string{"file", "file", "complete"}, events)
	mu.Unlock()
}

func TestPhase8CallbacksAreOrderedAndReentrantWithoutLocks(t *testing.T) {
	var manager *PcapWriterManager
	var mu sync.Mutex
	var events []string
	manager = newPhase8Manager(t, func(config *PcapWriterConfig) {
		config.OnFileClose = func(string) {
			assert.True(t, manager.IsFinalized("callbacks"))
			mu.Lock()
			events = append(events, "file")
			mu.Unlock()
		}
		config.OnCallComplete = func(CallMetadata) {
			err := manager.WritePacket("callbacks", "alice", "bob", time.Now(), []byte("late"), layers.LinkTypeEthernet, false)
			assert.True(t, IsCallFinalized(err))
			mu.Lock()
			events = append(events, "complete")
			mu.Unlock()
		}
	})
	require.NoError(t, manager.WritePacket("callbacks", "alice", "bob", time.Now(), []byte("sip"), layers.LinkTypeEthernet, false))

	done := make(chan error, 1)
	go func() {
		_, err := manager.FinalizeCall("callbacks", CallFinalizationProtocolComplete)
		done <- err
	}()
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("reentrant callback deadlocked on manager or writer lock")
	}
	mu.Lock()
	assert.Equal(t, []string{"file", "complete"}, events)
	mu.Unlock()
}

func TestPhase8IdleFinalizationCleansPortsAndTombstones(t *testing.T) {
	manager := newPhase8Manager(t, nil)
	monitor := NewCallCompletionMonitor(nil, nil, manager)
	cleaner := &recordingPortCleaner{}
	monitor.SetVoIPPortCleaner(cleaner)
	writer, err := manager.GetOrCreateWriter("idle", "alice", "bob")
	require.NoError(t, err)
	writer.mu.Lock()
	writer.lastWrite = time.Now().Add(-time.Hour)
	writer.mu.Unlock()

	assert.Equal(t, 1, manager.SweepIdle(time.Minute))
	assert.Equal(t, []string{"idle"}, cleaner.calls())
	assert.True(t, manager.IsFinalized("idle"))
	_, err = manager.GetOrCreateWriter("idle", "alice", "bob")
	assert.True(t, IsCallFinalized(err))
}

func TestPhase8CapacityEvictionReportsPressureWithoutCompletion(t *testing.T) {
	var completed atomic.Int32
	manager := newPhase8Manager(t, func(config *PcapWriterConfig) {
		config.MaxWriters = 1
		config.OnCallComplete = func(CallMetadata) { completed.Add(1) }
	})
	reasons := make(chan CallFinalizationReason, 1)
	manager.SetBeforeFinalize(func(_ string, reason CallFinalizationReason) { reasons <- reason })
	_, err := manager.GetOrCreateWriter("old", "alice", "bob")
	require.NoError(t, err)
	_, err = manager.GetOrCreateWriter("new", "carol", "dave")
	require.NoError(t, err)
	assert.Equal(t, CallFinalizationCapacityEviction, <-reasons)
	assert.Zero(t, completed.Load())
	assert.True(t, manager.IsFinalized("old"))
}

func TestPhase8ShutdownFlushesWithoutCompletionOrTombstone(t *testing.T) {
	var completed atomic.Int32
	var cleanup atomic.Int32
	manager := newPhase8Manager(t, func(config *PcapWriterConfig) {
		config.OnCallComplete = func(CallMetadata) { completed.Add(1) }
	})
	manager.SetBeforeFinalize(func(string, CallFinalizationReason) { cleanup.Add(1) })
	require.NoError(t, manager.WritePacket("shutdown", "alice", "bob", time.Now(), []byte("sip"), layers.LinkTypeEthernet, false))
	require.NoError(t, manager.Close())
	require.NoError(t, manager.Close())
	assert.Zero(t, completed.Load())
	assert.Zero(t, cleanup.Load())
	assert.False(t, manager.IsFinalized("shutdown"))
	err := manager.WritePacket("shutdown", "alice", "bob", time.Now(), []byte("late"), layers.LinkTypeEthernet, false)
	assert.Error(t, err)
	assert.False(t, errors.As(err, new(*FinalizedCallError)))
}

func TestPhase8ShutdownWaitsForDetachedFinalization(t *testing.T) {
	manager := newPhase8Manager(t, nil)
	require.NoError(t, manager.WritePacket("detached", "alice", "bob", time.Now(), []byte("sip"), layers.LinkTypeEthernet, false))

	finalizationStarted := make(chan struct{})
	releaseFinalization := make(chan struct{})
	manager.SetBeforeFinalize(func(string, CallFinalizationReason) {
		close(finalizationStarted)
		<-releaseFinalization
	})

	finalizeDone := make(chan error, 1)
	go func() {
		_, err := manager.FinalizeCall("detached", CallFinalizationProtocolComplete)
		finalizeDone <- err
	}()
	<-finalizationStarted

	closeDone := make(chan error, 1)
	go func() { closeDone <- manager.Close() }()
	select {
	case err := <-closeDone:
		require.NoError(t, err)
		t.Fatal("manager shutdown returned before detached finalization completed")
	case <-time.After(20 * time.Millisecond):
	}

	close(releaseFinalization)
	require.NoError(t, <-finalizeDone)
	require.NoError(t, <-closeDone)
}

func TestPhase8RotationCallbackCanInitiateShutdown(t *testing.T) {
	var manager *PcapWriterManager
	shutdownDone := make(chan error, 2)
	manager = newPhase8Manager(t, func(config *PcapWriterConfig) {
		config.MaxFileSize = 1
		config.OnFileClose = func(string) {
			shutdownDone <- manager.Close()
		}
	})
	require.NoError(t, manager.WritePacket("shutdown-callback", "alice", "bob", time.Now(), []byte{1}, layers.LinkTypeEthernet, false))

	writeDone := make(chan error, 1)
	go func() {
		writeDone <- manager.WritePacket("shutdown-callback", "alice", "bob", time.Now(), []byte{2}, layers.LinkTypeEthernet, false)
	}()

	select {
	case err := <-shutdownDone:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("rotation callback deadlocked while initiating shutdown")
	}
	select {
	case err := <-writeDone:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("packet write did not return after callback-initiated shutdown")
	}
}

func TestPhase8CallbackPanicsDoNotStrandFinalization(t *testing.T) {
	manager := newPhase8Manager(t, func(config *PcapWriterConfig) {
		config.OnFileClose = func(string) { panic("file callback") }
		config.OnCallComplete = func(CallMetadata) { panic("completion callback") }
	})
	manager.SetBeforeFinalize(func(string, CallFinalizationReason) { panic("cleanup callback") })
	require.NoError(t, manager.WritePacket("panicking-callbacks", "alice", "bob", time.Now(), []byte{1}, layers.LinkTypeEthernet, false))

	result, err := manager.FinalizeCall("panicking-callbacks", CallFinalizationProtocolComplete)
	require.NoError(t, err)
	assert.True(t, result.Finalized)

	closeDone := make(chan error, 1)
	go func() { closeDone <- manager.Close() }()
	select {
	case err := <-closeDone:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("callback panic stranded finalization bookkeeping")
	}
}
