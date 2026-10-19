// Package admissionadapter projects temporary subject lifetimes onto local
// candidate-admission owner capabilities. Remote subject IDs are never reused as
// local controller tokens. Exact transport, direction and qualifier enforcement
// remains in the learned-rule matcher; backend endpoint maps are conservative
// candidate filters, not exact generic matchers.
package admissionadapter

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/endorses/lippycat/internal/pkg/learnedrules"
	"github.com/endorses/lippycat/internal/pkg/mediaadmission"
)

type ownerKey struct {
	Session        learnedrules.Session
	AdapterID      string
	ContextVersion uint32
	Subject        learnedrules.Subject
	Domain         mediaadmission.DomainID
}

type Projection struct {
	mu         sync.Mutex
	ctx        context.Context
	controller *mediaadmission.Controller
	domains    []mediaadmission.DomainID
	sourceID   string
	owners     map[ownerKey]mediaadmission.OwnerID
	change     learnedrules.Change
	ready      bool
	lastErr    error
	onError    func(error)
}

// New retains the domain-only compatibility projection. Source runtimes must
// use NewForSource so another source's same-numbered domain cannot authorize it.
func New(ctx context.Context, controller *mediaadmission.Controller, domains []mediaadmission.DomainID, onError func(error)) (*Projection, error) {
	return newProjection(ctx, controller, "", domains, onError)
}

// NewForSource projects only selectors scoped to the exact local source and a
// configured domain. Other scopes remain in the retained immutable binding.
func NewForSource(ctx context.Context, controller *mediaadmission.Controller, hunterID string, domains []mediaadmission.DomainID, onError func(error)) (*Projection, error) {
	if hunterID == "" {
		return nil, errors.New("learned candidate admission requires a source identity")
	}
	return newProjection(ctx, controller, hunterID, domains, onError)
}

func newProjection(ctx context.Context, controller *mediaadmission.Controller, sourceID string, domains []mediaadmission.DomainID, onError func(error)) (*Projection, error) {
	if ctx == nil || controller == nil || len(domains) == 0 {
		return nil, errors.New("learned candidate admission requires context, controller and domains")
	}
	seen := make(map[mediaadmission.DomainID]bool, len(domains))
	for _, domain := range domains {
		if seen[domain] {
			return nil, errors.New("duplicate learned candidate admission domain")
		}
		seen[domain] = true
	}
	return &Projection{ctx: ctx, controller: controller, sourceID: sourceID, domains: append([]mediaadmission.DomainID(nil), domains...), owners: make(map[ownerKey]mediaadmission.OwnerID), onError: onError}, nil
}

func (p *Projection) OnLearnedRulesChanged(change learnedrules.Change) {
	p.mu.Lock()
	if change.Sequence <= p.change.Sequence {
		p.mu.Unlock()
		return
	}
	// Retain only owned data required for reconciliation and retries.
	p.change = ownChange(change)
	err := p.reconcileLocked()
	p.mu.Unlock()
	if err != nil && p.onError != nil {
		p.onError(err)
	}
}

// Ready is false until the complete desired snapshot was installed for this
// exact store observation. It certifies candidate admission only. Callers must
// also check the store lease, exact userspace matcher, and preceding capture
// filter capabilities before reporting complete source installation.
func (p *Projection) Ready(sequence uint64) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.ready && p.change.Ready && p.change.Sequence == sequence
}

func (p *Projection) Error() error { p.mu.Lock(); defer p.mu.Unlock(); return p.lastErr }

// Retry reconciles the retained full snapshot after transient backend failures.
func (p *Projection) Retry() error {
	p.mu.Lock()
	err := p.reconcileLocked()
	p.mu.Unlock()
	if err != nil && p.onError != nil {
		p.onError(err)
	}
	return err
}

func (p *Projection) reconcileLocked() error {
	p.ready = false
	base := p.ctx
	if !p.change.Ready {
		base = context.WithoutCancel(base)
	}
	ctx, cancel := context.WithTimeout(base, 10*time.Second)
	defer cancel()
	desired := make(map[ownerKey]map[mediaadmission.EndpointKey]struct{})
	if p.change.Ready {
		for _, binding := range p.change.Active {
			for _, selector := range binding.Selectors {
				if err := selector.Validate(); err != nil {
					p.lastErr = err
					return err
				}
				applicable, err := p.selectorInScope(binding, selector)
				if err != nil {
					p.lastErr = err
					return err
				}
				if !applicable {
					continue
				}
				endpoint := mediaadmission.EndpointKey{Domain: mediaadmission.DomainID(selector.Domain), Addr: selector.Address, Port: selector.Port}
				key := ownerKey{Session: binding.Session, AdapterID: binding.AdapterID, ContextVersion: binding.ContextVersion, Subject: binding.Subject, Domain: endpoint.Domain}
				if desired[key] == nil {
					desired[key] = make(map[mediaadmission.EndpointKey]struct{})
				}
				desired[key][endpoint] = struct{}{}
			}
		}
	}
	preliminary := make(map[mediaadmission.DomainID][]error)
	var failures []error
	// Retire absent owners first so bounded capacity can be reused by a handover.
	for key, token := range p.owners {
		if _, keep := desired[key]; keep {
			continue
		}
		if err := p.controller.EndOwner(ctx, key.Domain, token); err != nil && !errors.Is(err, mediaadmission.ErrStaleOwner) {
			preliminary[key.Domain] = append(preliminary[key.Domain], err)
			continue
		}
		delete(p.owners, key)
	}
	for key := range desired {
		if _, exists := p.owners[key]; exists {
			continue
		}
		token, err := p.controller.BeginOwner(key.Domain, key.Subject.ID)
		if token != (mediaadmission.OwnerID{}) {
			p.owners[key] = token
		}
		if err != nil {
			preliminary[key.Domain] = append(preliminary[key.Domain], err)
		}
	}
	// ReplaceDesired consumes a complete domain snapshot and clears uncertainty;
	// retaining individual UpdateOwner successes alone would not prove completeness.
	for _, domain := range p.domains {
		var snapshot []mediaadmission.OwnerEndpoints
		missingOwner := false
		for key, endpoints := range desired {
			if key.Domain != domain {
				continue
			}
			token, exists := p.owners[key]
			if !exists {
				missingOwner = true
				continue
			}
			item := mediaadmission.OwnerEndpoints{Owner: token}
			for endpoint := range endpoints {
				item.Endpoints = append(item.Endpoints, endpoint)
			}
			snapshot = append(snapshot, item)
		}
		// A partial snapshot must not clear the controller's lost-observation
		// uncertainty. A later complete snapshot can recover retained reservations.
		if missingOwner {
			failures = append(failures, preliminary[domain]...)
			failures = append(failures, mediaadmission.ErrCapacity)
			continue
		}
		if err := p.controller.ReplaceDesired(ctx, domain, snapshot); err != nil {
			failures = append(failures, preliminary[domain]...)
			failures = append(failures, err)
		} else {
			// Successful full reconciliation proves the effects of earlier failed
			// retirement or reservation operations and supersedes their errors.
			for key := range p.owners {
				if key.Domain == domain {
					if _, keep := desired[key]; !keep {
						delete(p.owners, key)
					}
				}
			}
		}
	}
	p.lastErr = errors.Join(failures...)
	p.ready = p.lastErr == nil
	return p.lastErr
}

// ownChange keeps no borrowed binding slices. The projection only uses lifetime
// identity and selectors; proof and protocol context remain owned by the store.
func ownChange(change learnedrules.Change) learnedrules.Change {
	result := learnedrules.Change{Snapshot: learnedrules.Snapshot{Session: change.Session, Revision: change.Revision, Sequence: change.Sequence, Ready: change.Ready}}
	result.Active = make([]learnedrules.Binding, len(change.Active))
	for i, b := range change.Active {
		result.Active[i] = learnedrules.Binding{Session: b.Session, AdapterID: b.AdapterID, ContextVersion: b.ContextVersion, Subject: b.Subject, Scope: append([]learnedrules.Scope(nil), b.Scope...), Selectors: append([]learnedrules.Selector(nil), b.Selectors...)}
	}
	return result
}

// selectorInScope distinguishes an invalid unscoped selector from a valid leg
// intended for a different source. Domains are source-local namespaces.
func (p *Projection) selectorInScope(binding learnedrules.Binding, selector learnedrules.Selector) (bool, error) {
	configured := false
	for _, domain := range p.domains {
		if domain == mediaadmission.DomainID(selector.Domain) {
			configured = true
			break
		}
	}
	scoped, local := false, false
	for _, scope := range binding.Scope {
		if scope.Domain != selector.Domain {
			continue
		}
		if scope.HunterID == "" {
			return false, learnedrules.ErrScope
		}
		scoped = true
		if scope.HunterID == p.sourceID {
			local = true
		}
	}
	// The legacy domain-only constructor historically accepted already-local
	// observer values without scope. Keep that behavior only for local domains.
	if p.sourceID == "" && len(binding.Scope) == 0 {
		if !configured {
			return false, learnedrules.ErrScope
		}
		return true, nil
	}
	if !scoped {
		return false, learnedrules.ErrScope
	}
	return configured && (p.sourceID == "" || local), nil
}
