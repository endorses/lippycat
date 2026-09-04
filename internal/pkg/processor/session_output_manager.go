//go:build processor || tap || all

package processor

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/endorses/lippycat/internal/pkg/callregistry"
	"github.com/endorses/lippycat/internal/pkg/voip"
	"github.com/google/gopacket/layers"
)

var errSessionOutputClosed = errors.New("session output manager is closed")

type sessionCompletionMonitor interface {
	Start()
	Stop()
	SetVoIPPortCleaner(VoIPPortCleaner)
	ScheduleCloseReason(string, bool, CallFinalizationReason)
}

// OnCallStarted implements callregistry.LifecycleObserver. Writers are opened
// lazily by WritePacket, so a lifecycle start does not allocate output state.
func (m *SessionOutputManager) OnCallStarted(callregistry.Call) {}

// OnCallEnded schedules output closure without transferring registry state or
// writer ownership into the analyzer.
func (m *SessionOutputManager) OnCallEnded(call callregistry.Call, reason callregistry.EndReason) {
	if m == nil {
		return
	}
	m.lifecycleMu.RLock()
	defer m.lifecycleMu.RUnlock()
	if !m.closed && m.monitor != nil && reason != callregistry.EndShutdown {
		m.monitor.ScheduleCloseReason(
			call.CallID,
			call.State == "ACTIVE" || call.State == "ENDED",
			mapRegistryEndReason(reason),
		)
	}
}

var _ callregistry.LifecycleObserver = (*SessionOutputManager)(nil)

type sessionWriterCloser interface {
	Close() error
}

// SessionOutputManager owns all output resources whose lifetime is tied to a
// VoIP call. The call registry/aggregator owns call state; this manager merely
// observes that state and applies output policy (grace periods and PCAP close).
//
// Close excludes new writes before stopping lifecycle observation. It then
// closes the writers, ensuring callbacks cannot run before their files close.
type SessionOutputManager struct {
	writer    *PcapWriterManager
	lifecycle *CallLifecycleRegistry
	closer    sessionWriterCloser
	monitor   sessionCompletionMonitor

	lifecycleMu sync.RWMutex
	writesWG    sync.WaitGroup
	closed      bool
	startOnce   sync.Once
	closeOnce   sync.Once
	closeErr    error
}

func NewSessionOutputManager(
	writerConfig *PcapWriterConfig,
	monitorConfig *CallCompletionMonitorConfig,
	aggregator *voip.CallAggregator,
) (*SessionOutputManager, error) {
	monitorDefaults := monitorConfig
	if monitorDefaults == nil {
		monitorDefaults = DefaultCallCompletionMonitorConfig()
	}
	lifecycle := NewCallLifecycleRegistry(CallLifecycleConfig{TombstoneTTL: monitorDefaults.ClosedCallTTL})
	var writer *PcapWriterManager
	if writerConfig != nil && writerConfig.Enabled {
		var err error
		writer, err = NewPcapWriterManagerWithLifecycle(writerConfig, lifecycle)
		if err != nil {
			return nil, fmt.Errorf("create per-call PCAP writer manager: %w", err)
		}
	}

	return newSessionOutputManagerWithLifecycle(
		writer,
		NewCallCompletionMonitorWithLifecycle(monitorConfig, aggregator, writer, lifecycle),
		lifecycle,
	), nil
}

func newSessionOutputManager(writer *PcapWriterManager, monitor sessionCompletionMonitor) *SessionOutputManager {
	var lifecycle *CallLifecycleRegistry
	if writer != nil {
		lifecycle = writer.lifecycle
	}
	return newSessionOutputManagerWithLifecycle(writer, monitor, lifecycle)
}

func newSessionOutputManagerWithLifecycle(writer *PcapWriterManager, monitor sessionCompletionMonitor, lifecycle *CallLifecycleRegistry) *SessionOutputManager {
	manager := &SessionOutputManager{writer: writer, lifecycle: lifecycle, monitor: monitor}
	if writer != nil {
		manager.closer = writer
	}
	return manager
}

func (m *SessionOutputManager) Start() {
	if m == nil {
		return
	}
	m.startOnce.Do(func() {
		m.lifecycleMu.RLock()
		defer m.lifecycleMu.RUnlock()
		if !m.closed && m.monitor != nil {
			m.monitor.Start()
		}
	})
}

func (m *SessionOutputManager) SetVoIPPortCleaner(cleaner VoIPPortCleaner) {
	if m == nil {
		return
	}
	m.lifecycleMu.RLock()
	defer m.lifecycleMu.RUnlock()
	if !m.closed && m.monitor != nil {
		m.monitor.SetVoIPPortCleaner(cleaner)
	}
}

func (m *SessionOutputManager) Telemetry() PcapWriterTelemetry {
	if m == nil || m.writer == nil {
		return PcapWriterTelemetry{}
	}
	return m.writer.Telemetry()
}

// WritePacket registers an in-flight operation before releasing the lifecycle
// lock. Close first rejects new writes, then waits for admitted writes before
// closing the writer, without holding a lock across external callbacks.
func (m *SessionOutputManager) WritePacket(
	callID, from, to string,
	timestamp time.Time,
	data []byte,
	linkType layers.LinkType,
	isRTP bool,
) error {
	if m == nil {
		return nil
	}
	m.lifecycleMu.Lock()
	if m.closed {
		m.lifecycleMu.Unlock()
		return errSessionOutputClosed
	}
	writer := m.writer
	if writer != nil {
		m.writesWG.Add(1)
	}
	m.lifecycleMu.Unlock()
	if writer == nil {
		return nil
	}
	defer m.writesWG.Done()

	return writer.WritePacket(callID, from, to, timestamp, data, linkType, isRTP)
}

func (m *SessionOutputManager) writePacketWithAdmission(
	admission *CallAdmission,
	callID, from, to string,
	timestamp time.Time,
	data []byte,
	linkType layers.LinkType,
	isRTP bool,
) error {
	if m == nil {
		return nil
	}
	m.lifecycleMu.Lock()
	if m.closed {
		m.lifecycleMu.Unlock()
		return errSessionOutputClosed
	}
	writer := m.writer
	if writer != nil {
		m.writesWG.Add(1)
	}
	m.lifecycleMu.Unlock()
	if writer == nil {
		return nil
	}
	defer m.writesWG.Done()
	return writer.writePacketWithAdmission(admission, callID, from, to, timestamp, data, linkType, isRTP)
}

// Close is safe for concurrent use and preserves shutdown ordering: stop the
// lifecycle monitor first, then close all output writers.
func (m *SessionOutputManager) Close() error {
	if m == nil {
		return nil
	}
	m.closeOnce.Do(func() {
		m.lifecycleMu.Lock()
		m.closed = true
		monitor := m.monitor
		closer := m.closer
		m.lifecycleMu.Unlock()

		// Stop and close outside the lifecycle lock. Writer shutdown invokes
		// externally supplied file-close callbacks, which may safely re-enter
		// this manager and observe the terminal state.
		if monitor != nil {
			monitor.Stop()
		}
		m.writesWG.Wait()
		if m.lifecycle != nil {
			m.lifecycle.ShutdownAndWait()
		}
		if closer != nil {
			m.closeErr = closer.Close()
		}
	})
	return m.closeErr
}

func mapRegistryEndReason(reason callregistry.EndReason) CallFinalizationReason {
	switch reason {
	case callregistry.EndTimeout:
		return CallFinalizationIdleTimeout
	case callregistry.EndEvicted:
		return CallFinalizationCapacityEviction
	default:
		return CallFinalizationProtocolComplete
	}
}
