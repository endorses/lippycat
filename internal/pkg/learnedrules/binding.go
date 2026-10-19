package learnedrules

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
	"time"
)

func (s *Store) validateRule(b Binding, _ Revision, now time.Time) error {
	if b.ID == "" || b.Session != s.control.session || b.Revision == 0 || b.AdapterID == "" || b.ContextVersion == 0 || b.Subject.ID == "" || b.Subject.Incarnation == "" || b.AttributionContext == "" || len(b.Scope) == 0 || len(b.Selectors) == 0 || b.NotBefore.IsZero() || !b.ExpiresAt.After(b.NotBefore) {
		return ErrInvalid
	}
	if len(b.Selectors) > s.config.MaxEndpointsPerRule || len(b.Scope) > s.config.MaxEndpoints || len(b.Intents) > s.config.MaxRules || len(b.EvidenceRefs) > s.config.MaxRules || BindingBytes(b) > s.config.MaxBytes {
		return ErrCapacity
	}
	if b.ExpiresAt.Sub(b.NotBefore) > s.config.MaxLifetime || b.NotBefore.Sub(now) > s.config.MaxLifetime {
		return fmt.Errorf("binding lifetime: %w", ErrInvalid)
	}
	if !b.ExpiresAt.Add(-s.config.ClockUncertainty).After(now) {
		old, exists := s.rules[b.ID]
		if !exists || !sameOwner(old.rule, b) {
			return fmt.Errorf("expired binding cannot rearm capture: %w", ErrInvalid)
		}
	}
	a, ok := s.config.Registry.Lookup(b.AdapterID, b.ContextVersion)
	if !ok {
		return ErrUnsupported
	}
	applicable := s.config.HunterID == ""
	scopes := make(map[Scope]bool)
	for _, scope := range b.Scope {
		if scope.HunterID == "" || scopes[scope] {
			return ErrScope
		}
		scopes[scope] = true
		if scope.HunterID == s.config.HunterID && s.allowedDomain(scope.Domain) {
			applicable = true
		}
	}
	if !applicable {
		return ErrScope
	}
	seen := make(map[Selector]bool)
	for _, selector := range b.Selectors {
		if len(s.config.SupportedProtocols) > 0 && !slices.Contains(s.config.SupportedProtocols, selector.Protocol) {
			return ErrUnsupported
		}
		if err := selector.Validate(); err != nil || seen[selector] {
			return ErrInvalid
		}
		seen[selector] = true
		if selector.Qualifier.ID != "" && !slices.Contains(a.Qualifiers, selector.Qualifier) {
			return ErrUnsupported
		}
		found := false
		for _, scope := range b.Scope {
			if scope.Domain == selector.Domain {
				found = true
			}
		}
		if !found {
			return ErrScope
		}
	}
	intents := make(map[string]bool)
	for _, ref := range b.Intents {
		if ref.ID == "" || ref.Revision == 0 || intents[ref.ID] {
			return ErrInvalid
		}
		intents[ref.ID] = true
	}
	if err := a.Validate(CloneBinding(b)); err != nil {
		return err
	}
	return a.Authorize(CloneBinding(b))
}

func (s *Store) allowedDomain(domain DomainID) bool { return slices.Contains(s.config.Domains, domain) }

// InScope checks this source's eligibility without narrowing the immutable
// binding definition received from its authority. Store configuration is frozen.
func (s *Store) InScope(b Binding, domain DomainID) bool {
	if s.config.HunterID != "" && !s.allowedDomain(domain) {
		return false
	}
	for _, scope := range b.Scope {
		if scope.Domain == domain && (s.config.HunterID == "" || scope.HunterID == s.config.HunterID) {
			return true
		}
	}
	return false
}

// InScopeForSource checks exact source placement in a publisher's complete
// immutable binding without confusing independent local domain numberings.
func (s *Store) InScopeForSource(b Binding, sourceID string, domain DomainID) bool {
	if sourceID == "" || s.config.HunterID != "" && s.config.HunterID != sourceID || !s.InScope(b, domain) {
		return false
	}
	for _, scope := range b.Scope {
		if scope.HunterID == sourceID && scope.Domain == domain {
			return true
		}
	}
	return false
}

func sameOwner(a, b Binding) bool {
	return a.Session == b.Session && a.AdapterID == b.AdapterID && a.ContextVersion == b.ContextVersion && a.Subject == b.Subject && a.AttributionContext == b.AttributionContext
}

func equalRule(a, b Binding) bool {
	return sameOwner(a, b) && a.ID == b.ID && a.Revision == b.Revision && slices.Equal(a.Intents, b.Intents) && slices.Equal(a.EvidenceRefs, b.EvidenceRefs) && slices.Equal(a.Scope, b.Scope) && slices.Equal(a.Selectors, b.Selectors) && bytes.Equal(a.Context, b.Context) && bytes.Equal(a.Proof, b.Proof) && a.NotBefore.Equal(b.NotBefore) && a.ExpiresAt.Equal(b.ExpiresAt)
}

// CloneBinding isolates every mutable retained field from callers and observers.
func CloneBinding(b Binding) Binding {
	b.Intents = append([]IntentRef(nil), b.Intents...)
	b.EvidenceRefs = append([]string(nil), b.EvidenceRefs...)
	b.Scope = append([]Scope(nil), b.Scope...)
	b.Selectors = append([]Selector(nil), b.Selectors...)
	b.Context = append([]byte(nil), b.Context...)
	b.Proof = append([]byte(nil), b.Proof...)
	return b
}

func cloneRule(b Binding) Binding { return CloneBinding(b) }
func ruleBytes(b Binding) int     { return BindingBytes(b) }

// BindingBytes charges retained variable data and conservative bookkeeping,
// including references. This is accounting, not a process RSS bound.
func BindingBytes(b Binding) int {
	n := 384 + len(b.ID) + len(b.Session.ProcessorID) + len(b.AdapterID) + len(b.Subject.ID) + len(b.Subject.Incarnation) + len(b.AttributionContext) + len(b.Context) + len(b.Proof)
	for _, scope := range b.Scope {
		n += 32 + len(scope.HunterID)
	}
	for _, sel := range b.Selectors {
		n += 80 + len(sel.Qualifier.ID)
	}
	for _, ref := range b.Intents {
		n += 24 + len(ref.ID)
	}
	for _, ref := range b.EvidenceRefs {
		n += 16 + len(ref)
	}
	return n
}

func IsResyncError(err error) bool {
	return errors.Is(err, ErrRevision) || errors.Is(err, ErrNotReady) || errors.Is(err, ErrSession)
}
