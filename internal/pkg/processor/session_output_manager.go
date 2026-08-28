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
	ScheduleClose(string, bool)
}

// OnCallStarted implements callregistry.LifecycleObserver. Writers are opened
// lazily by WritePacket, so a lifecycle start does not allocate output state.
func (m *SessionOutputManager) OnCallStarted(callregistry.Call) {}

// OnCallEnded schedules output closure without transferring registry state or
// writer ownership into the analyzer.
func (m *SessionOutputManager) OnCallEnded(call callregistry.Call, _ callregistry.EndReason) {
	if m == nil {
		return
	}
	m.lifecycleMu.RLock()
	defer m.lifecycleMu.RUnlock()
	if !m.closed && m.monitor != nil {
		m.monitor.ScheduleClose(call.CallID, call.State == "ACTIVE" || call.State == "ENDED")
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
	writer  *PcapWriterManager
	closer  sessionWriterCloser
	monitor sessionCompletionMonitor

	lifecycleMu sync.RWMutex
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
	writer, err := NewPcapWriterManager(writerConfig)
	if err != nil {
		return nil, fmt.Errorf("create per-call PCAP writer manager: %w", err)
	}

	return newSessionOutputManager(writer, NewCallCompletionMonitor(monitorConfig, aggregator, writer)), nil
}

func newSessionOutputManager(writer *PcapWriterManager, monitor sessionCompletionMonitor) *SessionOutputManager {
	manager := &SessionOutputManager{writer: writer, monitor: monitor}
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

// WritePacket writes one packet while holding a shared lifecycle lease. Close
// takes the exclusive lease, so a writer can never be closed beneath a write.
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
	m.lifecycleMu.RLock()
	defer m.lifecycleMu.RUnlock()
	if m.closed {
		return errSessionOutputClosed
	}
	if m.writer == nil {
		return nil
	}

	writer, err := m.writer.GetOrCreateWriter(callID, from, to)
	if err != nil || writer == nil {
		return err
	}
	if isRTP {
		return writer.WriteRTPPacket(timestamp, data, linkType)
	}
	return writer.WriteSIPPacket(timestamp, data, linkType)
}

// Close is safe for concurrent use and preserves shutdown ordering: stop the
// lifecycle monitor first, then close all output writers.
func (m *SessionOutputManager) Close() error {
	if m == nil {
		return nil
	}
	m.closeOnce.Do(func() {
		m.lifecycleMu.Lock()
		defer m.lifecycleMu.Unlock()
		m.closed = true
		if m.monitor != nil {
			m.monitor.Stop()
		}
		if m.closer != nil {
			m.closeErr = m.closer.Close()
		}
	})
	return m.closeErr
}
