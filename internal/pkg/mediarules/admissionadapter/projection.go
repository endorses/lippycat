// Package admissionadapter projects temporary remote call lifetimes onto local
// media-admission owner capabilities. Remote registry IDs are never reused as
// local controller tokens.
package admissionadapter

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/endorses/lippycat/internal/pkg/callregistry"
	"github.com/endorses/lippycat/internal/pkg/mediaadmission"
	"github.com/endorses/lippycat/internal/pkg/mediarules"
)

type ownerKey struct {
	Session  mediarules.Session
	Lifetime callregistry.Lifetime
	CallID   string
	Domain   mediaadmission.DomainID
}

type Projection struct {
	mu         sync.Mutex
	ctx        context.Context
	controller *mediaadmission.Controller
	domains    []mediaadmission.DomainID
	owners     map[ownerKey]mediaadmission.OwnerID
	change     mediarules.Change
	ready      bool
	lastErr    error
	onError    func(error)
}

func New(ctx context.Context, controller *mediaadmission.Controller, domains []mediaadmission.DomainID, onError func(error)) (*Projection, error) {
	if ctx == nil || controller == nil || len(domains) == 0 {
		return nil, errors.New("remote media admission requires context, controller and domains")
	}
	return &Projection{ctx: ctx, controller: controller, domains: append([]mediaadmission.DomainID(nil), domains...), owners: make(map[ownerKey]mediaadmission.OwnerID), onError: onError}, nil
}

func (p *Projection) OnMediaRulesChanged(change mediarules.Change) {
	p.mu.Lock()
	if change.Sequence <= p.change.Sequence {
		p.mu.Unlock()
		return
	}
	p.change = change
	err := p.reconcileLocked()
	p.mu.Unlock()
	if err != nil && p.onError != nil {
		p.onError(err)
	}
}

// Ready is false until the complete desired snapshot was installed for this
// exact store observation. Callers must also check the store's current lease.
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
		for _, rule := range p.change.Active {
			for _, endpoint := range rule.Endpoints {
				key := ownerKey{Session: rule.Session, Lifetime: rule.Call.Lifetime, CallID: rule.Call.CallID, Domain: endpoint.Key.Domain}
				if desired[key] == nil {
					desired[key] = make(map[mediaadmission.EndpointKey]struct{})
				}
				desired[key][endpoint.Key] = struct{}{}
			}
		}
	}
	var failures []error
	// Retire absent owners first so bounded capacity can be reused by a handover.
	for key, token := range p.owners {
		if _, keep := desired[key]; keep {
			continue
		}
		if err := p.controller.EndOwner(ctx, key.Domain, token); err != nil && !errors.Is(err, mediaadmission.ErrStaleOwner) {
			failures = append(failures, err)
			continue
		}
		delete(p.owners, key)
	}
	for key := range desired {
		if _, exists := p.owners[key]; exists {
			continue
		}
		token, err := p.controller.BeginOwner(key.Domain, key.CallID)
		if token != (mediaadmission.OwnerID{}) {
			p.owners[key] = token
		}
		if err != nil {
			failures = append(failures, err)
		}
	}
	// ReplaceDesired consumes a complete domain snapshot and clears uncertainty;
	// retaining individual UpdateOwner successes alone would not prove completeness.
	for _, domain := range p.domains {
		var snapshot []mediaadmission.OwnerEndpoints
		for key, endpoints := range desired {
			if key.Domain != domain {
				continue
			}
			token, exists := p.owners[key]
			if !exists {
				continue
			}
			item := mediaadmission.OwnerEndpoints{Owner: token}
			for endpoint := range endpoints {
				item.Endpoints = append(item.Endpoints, endpoint)
			}
			snapshot = append(snapshot, item)
		}
		if err := p.controller.ReplaceDesired(ctx, domain, snapshot); err != nil {
			failures = append(failures, err)
		} else {
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
