package processor

import (
	"fmt"
	"sync"
	"time"

	"github.com/endorses/lippycat/internal/pkg/callregistry"
	"github.com/endorses/lippycat/internal/pkg/mediaadmission"
)

type timerKey struct {
	domain mediaadmission.DomainID
	callID string
}
type completionTimer struct {
	lifetime callregistry.Lifetime
	timer    *time.Timer
}
type scopedSource struct {
	mu       sync.Mutex
	config   mediaadmission.Config
	children map[mediaadmission.DomainID]*SourceAdapter
	grace    time.Duration
	timers   map[timerKey]completionTimer
	closed   bool
}

// NewScopedSourceAdapter isolates authoritative local calls and endpoint lookup
// by observation domain. Visible SIP Call-IDs are preserved. Central output's
// legacy Call-ID grouping is not authority to clean up any individual domain.
func NewScopedSourceAdapter(config mediaadmission.Config, children map[mediaadmission.DomainID]*SourceAdapter, grace time.Duration) (*SourceAdapter, error) {
	if grace < 0 {
		return nil, fmt.Errorf("negative scoped call completion grace")
	}
	state := &scopedSource{config: config, children: make(map[mediaadmission.DomainID]*SourceAdapter), grace: grace, timers: make(map[timerKey]completionTimer)}
	for _, domain := range config.Domains() {
		child := children[domain]
		if child == nil || child.proc == nil || child.scoped != nil {
			return nil, fmt.Errorf("missing local VoIP processor for domain %d", domain)
		}
		state.children[domain] = child
	}
	for domain, child := range state.children {
		domain, child := domain, child
		child.SetCompletionHandler(func(call callregistry.Call, reason callregistry.EndReason) {
			state.complete(domain, child, call, reason)
		})
	}
	return &SourceAdapter{scoped: state}, nil
}
func (s *scopedSource) child(iface string) *SourceAdapter {
	return s.children[s.config.DomainForInterface(iface)]
}
func (s *scopedSource) complete(domain mediaadmission.DomainID, child *SourceAdapter, call callregistry.Call, reason callregistry.EndReason) {
	active, ok := child.proc.Call(call.CallID)
	if !ok {
		return
	}
	if call.Lifetime.Session != 0 && call.Lifetime != active.Lifetime {
		return
	}
	lifetime := active.Lifetime
	if reason == callregistry.EndEvicted || reason == callregistry.EndShutdown {
		child.proc.FinalizeCallLifetime(call.CallID, lifetime)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	key := timerKey{domain, call.CallID}
	if old, ok := s.timers[key]; ok {
		if old.lifetime == lifetime {
			return
		}
		old.timer.Stop()
	}
	timer := time.AfterFunc(s.grace, func() {
		s.mu.Lock()
		entry, ok := s.timers[key]
		if !ok || entry.lifetime != lifetime || s.closed {
			s.mu.Unlock()
			return
		}
		delete(s.timers, key)
		s.mu.Unlock()
		child.proc.FinalizeCallLifetime(call.CallID, lifetime)
	})
	s.timers[key] = completionTimer{lifetime: lifetime, timer: timer}
}
func (s *scopedSource) close() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	for key, entry := range s.timers {
		entry.timer.Stop()
		delete(s.timers, key)
	}
	s.mu.Unlock()
	for _, child := range s.children {
		child.Close()
	}
}
func scopedCacheKey(domain mediaadmission.DomainID, call callregistry.Call) string {
	return fmt.Sprintf("%d/%d/%d/%s", domain, call.Lifetime.Session, call.Lifetime.Generation, call.CallID)
}

// FilterCacheKey includes the authoritative lifetime for isolated adapters.
// Unknown calls cannot inherit or create cached identity attribution.
func (a *SourceAdapter) FilterCacheKey(callID, iface string) string {
	if a.scoped == nil {
		return callID
	}
	child := a.scoped.child(iface)
	if child == nil {
		return ""
	}
	call, ok := child.proc.Call(callID)
	if !ok {
		return ""
	}
	return a.FilterCacheKeyForLifetime(callID, iface, call.Lifetime)
}

// FilterCacheKeyForLifetime prevents delayed packets from inheriting a reused dialog's identities.
func (a *SourceAdapter) FilterCacheKeyForLifetime(callID, iface string, lifetime callregistry.Lifetime) string {
	if callID == "" {
		return ""
	}
	if a.scoped == nil {
		return callID
	}
	domain := a.scoped.config.DomainForInterface(iface)
	child := a.scoped.children[domain]
	if child == nil {
		return ""
	}
	call, ok := child.proc.Call(callID)
	if !ok || call.Lifetime != lifetime {
		return ""
	}
	return scopedCacheKey(domain, call)
}

type selectionObserver struct {
	domain   mediaadmission.DomainID
	observer callregistry.LifecycleObserver
}

func (o selectionObserver) OnCallStarted(call callregistry.Call) {
	call.CallID = scopedCacheKey(o.domain, call)
	o.observer.OnCallStarted(call)
}
func (o selectionObserver) OnCallEnded(call callregistry.Call, reason callregistry.EndReason) {
	call.CallID = scopedCacheKey(o.domain, call)
	o.observer.OnCallEnded(call, reason)
}

// AddSelectionLifecycleObserver is separate from output lifecycle callbacks:
// cache keys carry scope/lifetime, while visible output Call-ID remains original.
func (a *SourceAdapter) AddSelectionLifecycleObserver(observer callregistry.LifecycleObserver) {
	if a == nil {
		return
	}
	if a.scoped == nil {
		a.AddLifecycleObserver(observer)
		return
	}
	for domain, child := range a.scoped.children {
		child.AddLifecycleObserver(selectionObserver{domain, observer})
	}
}
func (a *SourceAdapter) SetMediaObserver(observer interface {
	RecordAttributedMedia(string, callregistry.Lifetime)
}) {
	a.mediaObserver = observer
}
func (a *SourceAdapter) RecordAttributedMedia(callID, iface string, lifetime callregistry.Lifetime) {
	if a == nil {
		return
	}
	if a.scoped != nil {
		if child := a.scoped.child(iface); child != nil {
			child.RecordAttributedMedia(callID, iface, lifetime)
		}
		return
	}
	if a.mediaObserver != nil {
		a.mediaObserver.RecordAttributedMedia(callID, lifetime)
	}
}

// RecordAttributedPacket carries transient full-frame evidence only after the
// source has resolved media to an exact current selected call lifetime.
func (a *SourceAdapter) RecordAttributedPacket(callID, iface string, lifetime callregistry.Lifetime, frame []byte) {
	if a == nil {
		return
	}
	if a.scoped != nil {
		if child := a.scoped.child(iface); child != nil {
			child.RecordAttributedPacket(callID, iface, lifetime, frame)
		}
		return
	}
	if observer, ok := a.mediaObserver.(interface {
		RecordAttributedPacket(string, callregistry.Lifetime, []byte)
	}); ok {
		observer.RecordAttributedPacket(callID, lifetime, frame)
	}
}
