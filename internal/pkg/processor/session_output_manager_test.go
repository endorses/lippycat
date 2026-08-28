//go:build processor || tap || all

package processor

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/processor/source"
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
}

func (m *recordingSessionMonitor) Start()                             {}
func (m *recordingSessionMonitor) SetVoIPPortCleaner(VoIPPortCleaner) {}
func (m *recordingSessionMonitor) ScheduleClose(callID string, _ bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.scheduled = append(m.scheduled, callID)
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
