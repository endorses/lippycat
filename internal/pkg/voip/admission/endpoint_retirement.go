package admission

import (
	"errors"
	"net/netip"
	"time"

	"github.com/endorses/lippycat/internal/pkg/callregistry"
	"github.com/endorses/lippycat/internal/pkg/mediaadmission"
)

// retirementUsage includes one bounded per-lifetime descriptor and owned keys.
func retirementUsage(entries map[mediaadmission.EndpointKey]time.Time) mediaadmission.SelectedDerivationUsage {
	if len(entries) == 0 {
		return mediaadmission.SelectedDerivationUsage{}
	}
	return mediaadmission.SelectedDerivationUsage{Contexts: 1, Bytes: 128 + len(entries)*128, Endpoints: len(entries)}
}

// replaceRetirementsLocked changes accounting before publishing owned state.
func (b *Bridge) replaceRetirementsLocked(call *selectedCall, next map[mediaadmission.EndpointKey]time.Time) error {
	oldUsage, nextUsage := retirementUsage(call.retirements), retirementUsage(next)
	if err := b.cfg.Metadata.ReserveSelectedDerivation(oldUsage, nextUsage); err != nil {
		return err
	}
	b.derivationCount += nextUsage.Contexts - oldUsage.Contexts
	b.derivationBytes += nextUsage.Bytes - oldUsage.Bytes
	b.derivationEndpoints += nextUsage.Endpoints - oldUsage.Endpoints
	call.retirements = next
	if call.retirementFailed {
		failedWork := false
		for _, due := range next {
			if !due.After(call.retirementFailureAt) {
				failedWork = true
				break
			}
		}
		if !failedWork {
			call.retirementFailed = false
			call.retirementFailureAt = time.Time{}
		}
	}
	return nil
}

func (b *Bridge) scheduleRetirementsLocked(call *selectedCall, endpoints []mediaadmission.EndpointKey, now time.Time) error {
	if call.completing || b.cfg.Limits.Mode != mediaadmission.ModeEnforce || len(endpoints) == 0 {
		return nil
	}
	next := make(map[mediaadmission.EndpointKey]time.Time, len(call.retirements)+len(endpoints))
	for endpoint, due := range call.retirements {
		next[endpoint] = due
	}
	for _, endpoint := range endpoints {
		if _, exists := next[endpoint]; !exists {
			next[endpoint] = now.Add(b.cfg.RetirementGrace)
		}
	}
	if len(next) > b.cfg.Limits.MaxEndpointsPerOwner {
		call.contextLost = true
		return mediaadmission.ErrCapacity
	}
	if err := b.replaceRetirementsLocked(call, next); err != nil {
		call.contextLost = true
		return err
	}
	return nil
}

// Current complete proof and independent historical requirements cancel only
// the corresponding keys. Receipt of an ambiguous or partial offer is no proof.
func (b *Bridge) cancelRequiredRetirementsLocked(call *selectedCall) error {
	if len(call.retirements) == 0 {
		return nil
	}
	protected := make(map[mediaadmission.EndpointKey]bool)
	for _, state := range call.derivations {
		for _, endpoint := range state.retainedEndpoints {
			protected[endpoint] = true
		}
		if state.complete && !state.missing && !state.rejected && state.accepted {
			for _, endpoint := range state.endpoints {
				protected[endpoint] = true
			}
		}
	}
	next := make(map[mediaadmission.EndpointKey]time.Time, len(call.retirements))
	for endpoint, due := range call.retirements {
		if !protected[endpoint] {
			next[endpoint] = due
		}
	}
	return b.replaceRetirementsLocked(call, next)
}

func (b *Bridge) releaseRetirementsLocked(call *selectedCall) error {
	if len(call.retirements) == 0 {
		return nil
	}
	return b.replaceRetirementsLocked(call, nil)
}

// OnCallCompleting yields intermediate recovery cleanup to authoritative call
// completion grace. It cannot cancel work for a replacement Call-ID lifetime.
func (b *Bridge) OnCallCompleting(call callregistry.Call) {
	b.publicationMu.Lock()
	b.mu.Lock()
	state := b.selected[call.CallID]
	var err error
	if !b.closed && state != nil && state.lifetime == call.Lifetime {
		state.completing = true
		err = b.releaseRetirementsLocked(state)
	}
	b.mu.Unlock()
	b.publicationMu.Unlock()
	b.report(err)
}

// expireRetirements runs under publicationMu and uses the existing maintenance
// worker; no per-endpoint goroutine or timer survives a lifetime. Registry
// callbacks may reenter the bridge, so mutation never holds b.mu.
func (b *Bridge) expireRetirements(now time.Time) error {
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return nil
	}
	pending := make(map[string]callregistry.Lifetime)
	for id, state := range b.selected {
		if len(state.retirements) > 0 {
			pending[id] = state.lifetime
		}
	}
	b.mu.Unlock()
	var errs []error
	markFailure := func(id string, lifetime callregistry.Lifetime) {
		failed := false
		b.mu.Lock()
		if current := b.selected[id]; current != nil && current.lifetime == lifetime {
			current.retirementFailed = true
			failed = true
			if now.After(current.retirementFailureAt) {
				current.retirementFailureAt = now
			}
			b.needsSnapshot = true
		}
		b.mu.Unlock()
		if failed {
			errs = append(errs, b.cfg.Controller.MarkUnsynchronized(b.cfg.Domain, errors.New("selected endpoint retirement remains incomplete")))
		}
	}
	for id, lifetime := range pending {
		b.mu.Lock()
		state := b.selected[id]
		active, exists := b.cfg.Registry.Call(id)
		if state == nil || state.lifetime != lifetime {
			b.mu.Unlock()
			continue
		}
		if !exists || active.Lifetime != lifetime {
			errs = append(errs, b.releaseRetirementsLocked(state))
			b.mu.Unlock()
			continue
		}
		if err := b.cancelRequiredRetirementsLocked(state); err != nil {
			errs = append(errs, err)
			b.mu.Unlock()
			markFailure(id, lifetime)
			continue
		}
		var endpoints []string
		var keys []mediaadmission.EndpointKey
		for endpoint, due := range state.retirements {
			if !now.Before(due) {
				keys = append(keys, endpoint)
				endpoints = append(endpoints, netip.AddrPortFrom(endpoint.Addr, endpoint.Port).String())
			}
		}
		b.mu.Unlock()
		if len(endpoints) == 0 {
			continue
		}
		if !b.cfg.Registry.TryDissociateEndpointsForLifetime(id, lifetime, endpoints) {
			errs = append(errs, ErrCallUnavailable)
			markFailure(id, lifetime)
			continue
		}
		b.mu.Lock()
		if current := b.selected[id]; current != nil && current.lifetime == lifetime {
			next := make(map[mediaadmission.EndpointKey]time.Time, len(current.retirements))
			for key, due := range current.retirements {
				next[key] = due
			}
			for _, key := range keys {
				delete(next, key)
			}
			if err := b.replaceRetirementsLocked(current, next); err != nil {
				errs = append(errs, err)
				b.mu.Unlock()
				markFailure(id, lifetime)
				continue
			}
		}
		b.mu.Unlock()
	}
	return errors.Join(errs...)
}
