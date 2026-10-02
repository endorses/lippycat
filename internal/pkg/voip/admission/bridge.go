// Package admission joins validated local SIP metadata, authoritative call
// lifetimes, and optional kernel candidate admission. Output selection remains
// owned by the caller's existing SIP/VoIP pipeline.
package admission

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/endorses/lippycat/internal/pkg/callregistry"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/mediaadmission"
	"github.com/endorses/lippycat/internal/pkg/pipeline"
	"github.com/endorses/lippycat/internal/pkg/sip"
)

var ErrCallUnavailable = errors.New("selected local call lifetime is unavailable")
var bridgeSessions atomic.Uint64

type Registry interface {
	Call(string) (callregistry.Call, bool)
	EndpointSnapshot(string) (callregistry.EndpointObservation, bool)
	TryAssociateEndpointForLifetime(string, callregistry.Lifetime, string) bool
	AddObserver(callregistry.LifecycleObserver)
	AddEndpointObserver(callregistry.EndpointObserver)
}

type Diagnostics interface {
	RecordSelection(mediaadmission.OwnerID, mediaadmission.DomainID, bool, bool, time.Time)
	RecordAttributedMedia(mediaadmission.OwnerID)
	RecordFinalized(mediaadmission.OwnerID)
}

type Config struct {
	Diagnostics Diagnostics
	Domain      mediaadmission.DomainID
	Limits      mediaadmission.Config
	Registry    Registry
	Controller  *mediaadmission.Controller
	Metadata    *mediaadmission.MetadataStore
	OnError     func(error)
}

type Stats struct {
	IgnoredNonlocal      uint64
	UnkeyedMetadata      uint64
	MetadataErrors       uint64
	PromotionUnavailable uint64
	AssociationRejected  uint64
	StaleObservations    uint64
	SelectedLifetimes    int
}

type selectedCall struct {
	retry          bool
	answered       bool
	activeMedia    bool
	selectedAt     time.Time
	lifetime       callregistry.Lifetime
	owner          mediaadmission.OwnerID
	revision       uint64
	metadataCutoff uint64
}

type Bridge struct {
	stop         chan struct{}
	done         chan struct{}
	mu           sync.Mutex
	cfg          Config
	session      uint64
	nextMetadata uint64
	selected     map[string]*selectedCall
	stats        Stats
	closed       bool
}

func New(cfg Config) (*Bridge, error) {
	if cfg.Registry == nil || cfg.Controller == nil || cfg.Metadata == nil {
		return nil, errors.New("SIP admission requires registry, controller and metadata store")
	}
	if err := cfg.Limits.Validate(); err != nil {
		return nil, err
	}
	b := &Bridge{cfg: cfg, session: bridgeSessions.Add(1), selected: make(map[string]*selectedCall), stop: make(chan struct{}), done: make(chan struct{})}
	cfg.Registry.AddObserver(b)
	cfg.Registry.AddEndpointObserver(b)
	go b.retryLoop()
	return b, nil
}

func (b *Bridge) local(result pipeline.SIPResult) bool {
	return result.Packet != nil && result.Packet.Source.Kind == pipeline.SourceLiveCapture && b.cfg.Limits.DomainForInterface(result.Packet.Source.InterfaceName) == b.cfg.Domain
}
func (b *Bridge) report(err error) error {
	if err != nil && b.cfg.OnError != nil {
		b.cfg.OnError(err)
	}
	return err
}

// ObserveValidated retains only bounded normalized metadata. It is called after
// SIP framing/security validation, before a non-selected message returns.
func (b *Bridge) ObserveValidated(result pipeline.SIPResult) error {
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return mediaadmission.ErrClosed
	}
	if !b.local(result) {
		b.stats.IgnoredNonlocal++
		b.mu.Unlock()
		return nil
	}
	now := time.Now()
	candidates := b.cfg.Metadata.Candidates(b.cfg.Domain, b.session, result.CallID, now)
	// A final unsuccessful initial transaction cannot later be promoted. Existing
	// selected endpoint retirement remains the authoritative registry's policy.
	if result.ResponseCode >= 300 || (result.ResponseCode >= 200 && (result.CSeqMethod == "BYE" || result.CSeqMethod == "CANCEL")) {
		for _, record := range candidates {
			if compatible(record.Key, result) {
				b.cfg.Metadata.Delete(record.Key)
			}
		}
		b.mu.Unlock()
		return nil
	}
	// A tag-bearing response binds an earlier untagged offer to this fork. Keep
	// the original for other forks; each alias is charged to the same store bounds.
	var errs []error
	if result.ResponseCode > 100 && result.ResponseCode < 300 && result.FromTag != "" && result.ToTag != "" {
		for _, record := range candidates {
			if record.Key.ToTag != "" || !sameTransaction(record.Key, result) {
				continue
			}
			key := b.key(result, candidates)
			if err := b.cfg.Metadata.Observe(key, record.Endpoints, now); err != nil {
				b.stats.MetadataErrors++
				errs = append(errs, err)
			}
		}
	}
	if len(result.SDP) > 0 {
		if result.FromTag == "" && result.ViaBranch == "" {
			b.stats.UnkeyedMetadata++
		} else {
			parsed, err := sip.ParseSDPEndpoints(string(result.SDP), b.cfg.Limits.MaxEndpointsPerOwner)
			if err != nil {
				b.stats.MetadataErrors++
				errs = append(errs, err)
			} else {
				endpoints := make([]mediaadmission.EndpointKey, 0, len(parsed))
				for _, endpoint := range parsed {
					key, keyErr := mediaadmission.NewEndpoint(b.cfg.Domain, endpoint.Address.Addr(), endpoint.Address.Port())
					if keyErr != nil {
						errs = append(errs, keyErr)
						continue
					}
					endpoints = append(endpoints, key)
				}
				key := b.key(result, b.cfg.Metadata.Candidates(b.cfg.Domain, b.session, result.CallID, now))
				if err = b.cfg.Metadata.Observe(key, endpoints, now); err != nil {
					b.stats.MetadataErrors++
					errs = append(errs, err)
				}
			}
		}
	}
	b.mu.Unlock()
	return b.report(errors.Join(errs...))
}

func (b *Bridge) key(result pipeline.SIPResult, candidates []mediaadmission.MetadataRecord) mediaadmission.DialogKey {
	key := mediaadmission.DialogKey{Domain: b.cfg.Domain, Session: b.session, CallID: result.CallID, FromTag: result.FromTag, ToTag: result.ToTag, Branch: result.ViaBranch, CSeq: result.CSeqNumber, CSeqMethod: result.CSeqMethod}
	for _, record := range candidates {
		old := record.Key
		if old.FromTag == key.FromTag && old.ToTag == key.ToTag && old.Branch == key.Branch && old.CSeq == key.CSeq && old.CSeqMethod == key.CSeqMethod {
			return old
		}
	}
	b.nextMetadata++
	key.Generation = b.nextMetadata
	return key
}

func sameTransaction(key mediaadmission.DialogKey, result pipeline.SIPResult) bool {
	return key.CallID == result.CallID && key.FromTag == result.FromTag && key.Branch != "" && key.Branch == result.ViaBranch && key.CSeq == result.CSeqNumber && key.CSeqMethod == result.CSeqMethod
}
func compatible(key mediaadmission.DialogKey, result pipeline.SIPResult) bool {
	if key.CallID != result.CallID {
		return false
	}
	if key.FromTag != "" && key.ToTag != "" && result.FromTag != "" && result.ToTag != "" {
		return (key.FromTag == result.FromTag && key.ToTag == result.ToTag) || (key.FromTag == result.ToTag && key.ToTag == result.FromTag)
	}
	// Without two established tags require exact transaction evidence, so an
	// unrelated later request cannot inherit an early offer from Call-ID alone.
	return sameTransaction(key, result) && (key.ToTag == "" || key.ToTag == result.ToTag)
}

// Selected runs after the authoritative local registry has accepted a selected
// message. Hunter adapters without a sipflow.Registry call it explicitly after
// creating/updating their tracker. It never manufactures a registry lifetime.
func (b *Bridge) Selected(result pipeline.SIPResult) error {
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return mediaadmission.ErrClosed
	}
	if !b.local(result) {
		b.stats.IgnoredNonlocal++
		b.mu.Unlock()
		return nil
	}
	call, ok := b.cfg.Registry.Call(result.CallID)
	if !ok || call.Lifetime.Session == 0 || call.Lifetime.Generation == 0 {
		b.mu.Unlock()
		return b.report(ErrCallUnavailable)
	}
	current := b.selected[result.CallID]
	var errs []error
	if current != nil && current.lifetime != call.Lifetime {
		if err := b.cfg.Controller.EndOwner(context.Background(), b.cfg.Domain, current.owner); err != nil && !errors.Is(err, mediaadmission.ErrStaleOwner) {
			errs = append(errs, err)
		}
		b.clearMetadata(result.CallID, current.metadataCutoff)
		if b.cfg.Diagnostics != nil {
			b.cfg.Diagnostics.RecordFinalized(current.owner)
		}
		delete(b.selected, result.CallID)
		current = nil
	}
	if current == nil {
		owner, err := b.cfg.Controller.BeginOwner(b.cfg.Domain, result.CallID)
		if err != nil {
			errs = append(errs, err)
			if owner.Session == 0 {
				// The bounded pending-token pool is exhausted or unavailable.
				// Controller keeps unknown desired state blocked; never retain an
				// unowned bridge entry or acknowledge this as complete recovery.
				b.mu.Unlock()
				return b.report(errors.Join(errs...))
			}
		}
		current = &selectedCall{lifetime: call.Lifetime, owner: owner, metadataCutoff: b.nextMetadata, selectedAt: time.Now(), retry: err != nil}
		b.selected[result.CallID] = current
	}
	now := time.Now()
	var promote []mediaadmission.EndpointKey
	for _, record := range b.cfg.Metadata.Candidates(b.cfg.Domain, b.session, result.CallID, now) {
		if !compatible(record.Key, result) {
			continue
		}
		endpoints, found := b.cfg.Metadata.Take(record.Key, now)
		if found {
			promote = append(promote, endpoints...)
			current.metadataCutoff = b.nextMetadata
		}
	}
	if len(promote) == 0 && len(result.SDP) == 0 {
		b.stats.PromotionUnavailable++
	}
	if result.ResponseCode >= 200 && result.ResponseCode < 300 && result.CSeqMethod == "INVITE" {
		current.answered = true
	}
	if len(result.SDP) > 0 {
		if endpoints, err := sip.ParseSDPEndpoints(string(result.SDP), b.cfg.Limits.MaxEndpointsPerOwner); err == nil {
			current.activeMedia = len(endpoints) > 0
		}
	} else if len(promote) > 0 {
		current.activeMedia = true
	}
	if b.cfg.Diagnostics != nil {
		b.cfg.Diagnostics.RecordSelection(current.owner, b.cfg.Domain, current.answered, current.activeMedia, current.selectedAt)
	}
	lifetime := call.Lifetime
	b.mu.Unlock()
	// Registry endpoint callbacks reenter this bridge, so promotion happens with
	// no bridge lock held. The registry enforces the exact captured lifetime.
	for _, endpoint := range promote {
		if !b.cfg.Registry.TryAssociateEndpointForLifetime(result.CallID, lifetime, netip.AddrPortFrom(endpoint.Addr, endpoint.Port).String()) {
			b.mu.Lock()
			b.stats.AssociationRejected++
			b.mu.Unlock()
			errs = append(errs, errors.New("authoritative registry rejected promoted media endpoint"))
		}
	}
	if snapshot, exists := b.cfg.Registry.EndpointSnapshot(result.CallID); exists && snapshot.Call.Lifetime == lifetime {
		if err := b.apply(snapshot); err != nil {
			errs = append(errs, err)
		}
	} else {
		errs = append(errs, ErrCallUnavailable)
	}
	return b.report(errors.Join(errs...))
}

func parseEndpoint(domain mediaadmission.DomainID, endpoint string) (mediaadmission.EndpointKey, error) {
	address, err := netip.ParseAddrPort(endpoint)
	if err != nil {
		// Legacy tracker indexes concatenate IPv6 and port without brackets.
		if split := strings.LastIndexByte(endpoint, ':'); split > 0 {
			address, err = netip.ParseAddrPort("[" + endpoint[:split] + "]" + endpoint[split:])
		}
	}
	if err != nil {
		return mediaadmission.EndpointKey{}, err
	}
	return mediaadmission.NewEndpoint(domain, address.Addr(), address.Port())
}
func (b *Bridge) apply(observation callregistry.EndpointObservation) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return nil
	}
	state := b.selected[observation.Call.CallID]
	if state == nil || state.lifetime != observation.Call.Lifetime {
		return nil
	}
	current, active := b.cfg.Registry.EndpointSnapshot(observation.Call.CallID)
	if !active || current.Call.Lifetime != observation.Call.Lifetime || observation.Revision < state.revision || current.Revision < state.revision {
		b.stats.StaleObservations++
		return nil
	}
	// Endpoint revisions are registry-wide. An unrelated call can advance the
	// sequence between callback delivery and this read without invalidating
	// this call's accepted endpoints. Publish the freshly captured exact-lifetime
	// snapshot; never discard a required update solely for global sequence drift.
	observation = current
	endpoints := make([]mediaadmission.EndpointKey, 0, len(observation.Endpoints))
	for _, endpoint := range observation.Endpoints {
		// Port-only entries remain non-authoritative diagnostics; never admit them.
		if !strings.Contains(endpoint, ":") {
			continue
		}
		key, err := parseEndpoint(b.cfg.Domain, endpoint)
		if err != nil {
			state.retry = true
			return b.cfg.Controller.MarkUnsynchronized(b.cfg.Domain, fmt.Errorf("invalid authoritative media endpoint: %w", err))
		}
		endpoints = append(endpoints, key)
	}
	state.revision = observation.Revision
	err := b.cfg.Controller.UpdateOwner(context.Background(), b.cfg.Domain, state.owner, endpoints)
	state.retry = err != nil
	return err
}
func (b *Bridge) OnEndpointsChanged(observation callregistry.EndpointObservation) {
	b.report(b.apply(observation))
}
func (b *Bridge) OnCallStarted(call callregistry.Call) {
	b.mu.Lock()
	old := b.selected[call.CallID]
	// A delayed start notification is not evidence of a new active lifetime.
	active, ok := b.cfg.Registry.Call(call.CallID)
	if b.closed || !ok || active.Lifetime != call.Lifetime || old == nil || old.lifetime == call.Lifetime {
		b.mu.Unlock()
		return
	}
	delete(b.selected, call.CallID)
	err := b.cfg.Controller.EndOwner(context.Background(), b.cfg.Domain, old.owner)
	b.clearMetadata(call.CallID, old.metadataCutoff)
	if b.cfg.Diagnostics != nil {
		b.cfg.Diagnostics.RecordFinalized(old.owner)
	}
	b.mu.Unlock()
	if !errors.Is(err, mediaadmission.ErrStaleOwner) {
		b.report(err)
	}
}
func (b *Bridge) OnCallEnded(call callregistry.Call, _ callregistry.EndReason) {
	b.mu.Lock()
	old := b.selected[call.CallID]
	if b.closed || old == nil || old.lifetime != call.Lifetime {
		b.mu.Unlock()
		return
	}
	delete(b.selected, call.CallID)
	err := b.cfg.Controller.EndOwner(context.Background(), b.cfg.Domain, old.owner)
	b.clearMetadata(call.CallID, old.metadataCutoff)
	if b.cfg.Diagnostics != nil {
		b.cfg.Diagnostics.RecordFinalized(old.owner)
	}
	b.mu.Unlock()
	if !errors.Is(err, mediaadmission.ErrStaleOwner) {
		b.report(err)
	}
}
func (b *Bridge) Stats() Stats {
	b.mu.Lock()
	defer b.mu.Unlock()
	stats := b.stats
	stats.SelectedLifetimes = len(b.selected)
	return stats
}
func (b *Bridge) Close() error {
	b.mu.Lock()
	// The retry worker never invokes user callbacks. Release its lock before
	// joining so a pending retry can observe closed and exit.
	defer func() { b.mu.Unlock(); <-b.done }()
	if b.closed {
		return nil
	}
	b.closed = true
	close(b.stop)
	var errs []error
	for _, state := range b.selected {
		if b.cfg.Diagnostics != nil {
			b.cfg.Diagnostics.RecordFinalized(state.owner)
		}
		if err := b.cfg.Controller.EndOwner(context.Background(), b.cfg.Domain, state.owner); err != nil && !errors.Is(err, mediaadmission.ErrStaleOwner) {
			errs = append(errs, err)
		}
	}
	b.selected = make(map[string]*selectedCall)
	if len(errs) > 0 {
		// Retiring one owner can remain incomplete until the other pending
		// owners are retired too. Validate the final current set once, rather
		// than treating those intermediate transitions as failed cleanup.
		if err := b.cfg.Controller.Reconcile(context.Background(), b.cfg.Domain); err != nil {
			return errors.Join(append(errs, err)...)
		}
		logger.Debug("Media admission cleanup reconciled incomplete transitions", "domain", b.cfg.Domain, "transitions", len(errs))
	}
	return nil
}

// clearMetadata never deletes a newer observation created after this selected
// lifetime's last metadata transition, even if its completion callback is late.
// Taken records need no per-call bookkeeping: the store already removed them.
func (b *Bridge) clearMetadata(callID string, cutoff uint64) {
	for _, record := range b.cfg.Metadata.Candidates(b.cfg.Domain, b.session, callID, time.Now()) {
		if record.Key.Generation <= cutoff {
			b.cfg.Metadata.Delete(record.Key)
		}
	}
}

// RecordAttributedMedia is called only after the caller's authoritative exact
// endpoint resolution. A retired/reused lifetime cannot update the new owner's
// diagnostic record through a delayed callback.
func (b *Bridge) RecordAttributedMedia(callID string, lifetime callregistry.Lifetime) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed || b.cfg.Diagnostics == nil {
		return
	}
	state := b.selected[callID]
	if state == nil {
		return
	}
	call, ok := b.cfg.Registry.Call(callID)
	if !ok || call.Lifetime != state.lifetime || lifetime != state.lifetime {
		return
	}
	b.cfg.Diagnostics.RecordAttributedMedia(state.owner)
}

// retryLoop restores rejected eligible observations even when a dialog sends no
// further SDP. Only stable tokens are retained; the registry owns all endpoints.
func (b *Bridge) retryLoop() {
	defer close(b.done)
	ticker := time.NewTicker(b.cfg.Limits.RetryInterval)
	defer ticker.Stop()
	for {
		select {
		case <-b.stop:
			return
		case <-ticker.C:
			if err := b.retrySelected(); err != nil {
				// Errors and effective failure policy are already in controller
				// status. Do not reenter OnError here: it may synchronously Close.
				logger.Debug("Media admission retry remains incomplete", "domain", b.cfg.Domain)
			}
		}
	}
}

func (b *Bridge) retrySelected() error {
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return nil
	}
	pending := make(map[string]callregistry.Lifetime)
	for id, state := range b.selected {
		if state.retry {
			pending[id] = state.lifetime
		}
	}
	b.mu.Unlock()
	var errs []error
	for id, lifetime := range pending {
		observation, ok := b.cfg.Registry.EndpointSnapshot(id)
		if !ok || observation.Call.Lifetime != lifetime {
			continue
		}
		if err := b.apply(observation); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
