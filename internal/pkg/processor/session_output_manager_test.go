//go:build processor || tap || all

package processor

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/callregistry"
	"github.com/endorses/lippycat/internal/pkg/processor/source"
	"github.com/endorses/lippycat/internal/pkg/voip"
	voipprocessor "github.com/endorses/lippycat/internal/pkg/voip/processor"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type recordingSessionMonitor struct {
	mu        sync.Mutex
	events    *[]string
	stops     atomic.Int32
	scheduled []string
	reasons   []CallFinalizationReason
}

func (m *recordingSessionMonitor) Start()                             {}
func (m *recordingSessionMonitor) SetVoIPPortCleaner(VoIPPortCleaner) {}
func (m *recordingSessionMonitor) ScheduleCloseReason(callID string, _ bool, reason CallFinalizationReason) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.scheduled = append(m.scheduled, callID)
	m.reasons = append(m.reasons, reason)
}
func (m *recordingSessionMonitor) Stop() {
	m.stops.Add(1)
	m.mu.Lock()
	*m.events = append(*m.events, "monitor stopped")
	m.mu.Unlock()
}

type recordingSessionCloser struct {
	mu     *sync.Mutex
	events *[]string
	closes atomic.Int32
	err    error
}

func (c *recordingSessionCloser) Close() error {
	c.closes.Add(1)
	c.mu.Lock()
	*c.events = append(*c.events, "writers closed")
	c.mu.Unlock()
	return c.err
}

func TestSessionOutputManagerCloseOrderingAndConcurrentIdempotence(t *testing.T) {
	var eventsMu sync.Mutex
	events := make([]string, 0, 2)
	monitor := &recordingSessionMonitor{events: &events}
	closer := &recordingSessionCloser{mu: &eventsMu, events: &events, err: errors.New("close failed")}
	manager := newSessionOutputManager(nil, monitor)
	manager.closer = closer

	const callers = 32
	errs := make(chan error, callers)
	var wg sync.WaitGroup
	for range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- manager.Close()
		}()
	}
	wg.Wait()
	close(errs)

	for err := range errs {
		require.EqualError(t, err, "close failed")
	}
	assert.Equal(t, int32(1), monitor.stops.Load())
	assert.Equal(t, int32(1), closer.closes.Load())
	assert.Equal(t, []string{"monitor stopped", "writers closed"}, events)
}

func TestSessionOutputManagerRejectsWritesAfterClose(t *testing.T) {
	manager := newSessionOutputManager(nil, nil)
	require.NoError(t, manager.Close())

	err := manager.WritePacket(
		"call-id", "alice", "bob", time.Now(), []byte{1}, layers.LinkTypeEthernet, false,
	)
	require.ErrorIs(t, err, errSessionOutputClosed)
}

func TestSessionOutputManagerShutdownCallbackCanReenter(t *testing.T) {
	var manager *SessionOutputManager
	callbackDone := make(chan error, 1)
	writer, err := NewPcapWriterManager(&PcapWriterConfig{
		Enabled:      true,
		OutputDir:    t.TempDir(),
		FilePattern:  "{callid}.pcap",
		SyncInterval: time.Hour,
		OnFileClose: func(string) {
			callbackDone <- manager.WritePacket(
				"reentrant", "alice", "bob", time.Now(), []byte{2}, layers.LinkTypeEthernet, false,
			)
		},
	})
	require.NoError(t, err)
	manager = newSessionOutputManager(writer, nil)
	require.NoError(t, manager.WritePacket(
		"shutdown", "alice", "bob", time.Now(), []byte{1}, layers.LinkTypeEthernet, false,
	))

	closeDone := make(chan error, 1)
	go func() { closeDone <- manager.Close() }()

	select {
	case err := <-callbackDone:
		require.ErrorIs(t, err, errSessionOutputClosed)
	case <-time.After(time.Second):
		t.Fatal("file-close callback deadlocked while re-entering session output manager")
	}
	select {
	case err := <-closeDone:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("session output manager shutdown deadlocked")
	}
}

func TestSetPacketSourceRegistersSessionOutputLifecycleObserver(t *testing.T) {
	monitor := &recordingSessionMonitor{}
	manager := newSessionOutputManager(nil, monitor)
	registry := voipprocessor.New(voipprocessor.Config{MaxCalls: 10, CallTimeout: time.Hour})
	t.Cleanup(registry.Close)
	localSource := source.NewLocalSource(source.DefaultLocalSourceConfig())
	localSource.SetVoIPProcessor(voipprocessor.NewSourceAdapter(registry))
	p := &Processor{sessionOutputManager: manager}

	p.SetPacketSource(localSource)
	registry.AssociateEndpoint("call-id", "192.0.2.1:10000")
	registry.CompleteCall("call-id")

	monitor.mu.Lock()
	defer monitor.mu.Unlock()
	require.Equal(t, []string{"call-id"}, monitor.scheduled)
}

func TestLocalCompletionCleanupWaitsForSharedFinalization(t *testing.T) {
	lifecycle := NewCallLifecycleRegistry(CallLifecycleConfig{TombstoneTTL: time.Hour})
	monitor := NewCallCompletionMonitorWithLifecycle(nil, nil, nil, lifecycle)
	manager := newSessionOutputManagerWithLifecycle(nil, monitor, lifecycle)
	registry := voipprocessor.New(voipprocessor.Config{MaxCalls: 10, CallTimeout: time.Hour})
	t.Cleanup(registry.Close)
	localSource := source.NewLocalSource(source.DefaultLocalSourceConfig())
	localSource.SetVoIPProcessor(voipprocessor.NewSourceAdapter(registry))
	manager.SetVoIPPortCleaner(localSource)
	p := &Processor{sessionOutputManager: manager}
	p.SetPacketSource(localSource)

	registry.AssociateEndpoint("shared-boundary", "192.0.2.30:13000")
	registry.CompleteCall("shared-boundary")
	require.Equal(t, []string{"shared-boundary"}, registry.CallIDsForEndpoint("192.0.2.30:13000"),
		"terminal signaling must retain attribution during the grace period")

	result := lifecycle.Finalize("shared-boundary", CallFinalizationProtocolComplete)
	require.True(t, result.Finalized)
	require.Empty(t, registry.CallIDsForEndpoint("192.0.2.30:13000"),
		"shared finalization must clean attribution")
	_, exists := registry.Call("shared-boundary")
	require.False(t, exists)
}

func TestSessionOutputManagerMapsEndReasonsAndIgnoresShutdown(t *testing.T) {
	monitor := &recordingSessionMonitor{}
	manager := newSessionOutputManagerWithLifecycle(nil, monitor, NewCallLifecycleRegistry(CallLifecycleConfig{}))

	manager.OnCallEnded(callregistry.Call{CallID: "completed"}, callregistry.EndCompleted)
	manager.OnCallEnded(callregistry.Call{CallID: "timeout"}, callregistry.EndTimeout)
	manager.OnCallEnded(callregistry.Call{CallID: "evicted"}, callregistry.EndEvicted)
	manager.OnCallEnded(callregistry.Call{CallID: "shutdown"}, callregistry.EndShutdown)

	monitor.mu.Lock()
	defer monitor.mu.Unlock()
	assert.Equal(t, []string{"completed", "timeout", "evicted"}, monitor.scheduled)
	assert.Equal(t, []CallFinalizationReason{
		CallFinalizationProtocolComplete,
		CallFinalizationIdleTimeout,
		CallFinalizationCapacityEviction,
	}, monitor.reasons)
}

func TestNewSessionOutputManagerWithoutPCAPOwnsLifecycle(t *testing.T) {
	manager, err := NewSessionOutputManager(nil, nil, voip.NewCallAggregator())
	require.NoError(t, err)
	require.NotNil(t, manager.lifecycle)
	assert.Nil(t, manager.writer)
	require.NoError(t, manager.Close())
	_, err = manager.lifecycle.Admit("after-shutdown")
	assert.ErrorIs(t, err, ErrCallLifecycleShutdown)
}
