//go:build li

package iripolicy

import (
	"fmt"
	"slices"

	"github.com/google/uuid"
)

// Compiled is an immutable policy snapshot. It owns all of its rules, dictionary
// indexes, and source generations and is safe for concurrent evaluation.
type Compiled struct {
	rules       []*Rule
	profile     profileIndex
	generations map[uuid.UUID]uint64
}

// Compile validates the complete detached object graph and compiles the requested
// policies in supplied order. Within each policy, positive rule orders are sorted
// ascending. The first matching rule across the entire list decides delivery.
// Referenced source generations must be nonzero. No policy or no matching rule
// means Delivered, as specified by TS 103 120.
func Compile(policyIDs []uuid.UUID, objects []Object, profile Profile, limits Limits) (*Compiled, error) {
	resolved, err := resolveLimits(limits)
	if err != nil {
		return nil, err
	}
	if len(policyIDs) > resolved.MaxPolicyReferences {
		return nil, fmt.Errorf("policy references: %w", ErrLimitExceeded)
	}
	profileIndex, err := indexProfile(profile)
	if err != nil {
		return nil, err
	}
	index, err := indexObjects(objects, profileIndex, resolved)
	if err != nil {
		return nil, err
	}
	compiled := &Compiled{
		profile:     profileIndex,
		generations: make(map[uuid.UUID]uint64),
	}
	seenPolicies := make(map[uuid.UUID]struct{}, len(policyIDs))
	ownedRules := make(map[uuid.UUID]*Rule)
	for i, id := range policyIDs {
		if _, exists := seenPolicies[id]; exists {
			return nil, fmt.Errorf("policy reference %d: %w", i, ErrDuplicateReference)
		}
		object, exists := index[id]
		if !exists {
			return nil, fmt.Errorf("policy reference %d: %w", i, ErrMissingObject)
		}
		if object.Policy == nil {
			return nil, fmt.Errorf("policy reference %d: %w", i, ErrWrongObjectKind)
		}
		if object.Generation == 0 {
			return nil, fmt.Errorf("policy reference %d: %w", i, ErrInvalidGeneration)
		}
		seenPolicies[id] = struct{}{}
		compiled.generations[id] = object.Generation
		references := slices.Clone(object.Policy.Rules)
		slices.SortFunc(references, compareReferences)
		for j, reference := range references {
			rule := index[reference.ObjectID]
			if rule.Generation == 0 {
				return nil, fmt.Errorf("policy reference %d rule reference %d: %w", i, j, ErrInvalidGeneration)
			}
			owned, exists := ownedRules[rule.ID]
			if !exists {
				owned = CloneObject(rule).Rule
				ownedRules[rule.ID] = owned
			}
			compiled.rules = append(compiled.rules, owned)
			compiled.generations[rule.ID] = rule.Generation
		}
	}
	return compiled, nil
}

// SourceGenerations returns a detached map of exactly the policies and rules
// used by this snapshot, allowing its owner to invalidate stale queued work.
func (c *Compiled) SourceGenerations() map[uuid.UUID]uint64 {
	if c == nil {
		return nil
	}
	generations := make(map[uuid.UUID]uint64, len(c.generations))
	for id, generation := range c.generations {
		generations[id] = generation
	}
	return generations
}

// Deliver evaluates delivery, suppressing it if required runtime facts are
// unavailable or invalid. Evaluate exposes the validation error to callers that
// need to distinguish that case from an explicit NotDelivered rule.
func (c *Compiled) Deliver(facts Facts) bool {
	deliver, err := c.Evaluate(facts)
	return err == nil && deliver
}

// Evaluate returns the action of the first matching rule, or Delivered when no
// rule matches. Evaluation fails closed if a reached criterion cannot be decided
// from reliable runtime facts. A nil snapshot has no policies and delivers.
func (c *Compiled) Evaluate(facts Facts) (bool, error) {
	if c == nil {
		return true, nil
	}
	for i, rule := range c.rules {
		match, err := c.matchesRule(rule, facts)
		if err != nil {
			return false, fmt.Errorf("rule %d: %w", i, err)
		}
		if match {
			return rule.Action.Value == "Delivered", nil
		}
	}
	return true, nil
}

func (c *Compiled) matchesRule(rule *Rule, facts Facts) (bool, error) {
	var unresolved error
	for i, criterion := range rule.Criteria {
		match, err := c.matchesCriterion(criterion, facts)
		if err != nil {
			if unresolved == nil {
				unresolved = fmt.Errorf("criterion %d: %w", i, err)
			}
			continue
		}
		if !match {
			return false, nil
		}
	}
	if unresolved != nil {
		return false, unresolved
	}
	return true, nil
}

func (c *Compiled) matchesCriterion(criterion Criterion, facts Facts) (bool, error) {
	if len(criterion.NFTypes) != 0 {
		return matchesEntries(criterion.NFTypes, facts.NFTypes, c.profile.nfTypes, facts.NFTypesKnown)
	}
	if len(criterion.Events) != 0 {
		for _, entry := range criterion.Events {
			if isAllEvents(entry) {
				return true, nil
			}
		}
		return matchesEntries(criterion.Events, facts.Events, c.profile.events, facts.EventsKnown)
	}
	if facts.HandoverFormat == nil {
		return false, ErrInvalidFacts
	}
	if _, exists := c.profile.handoverFormats[*facts.HandoverFormat]; !exists {
		return false, ErrInvalidFacts
	}
	return *criterion.HandoverFormat == *facts.HandoverFormat, nil
}

func matchesEntries(criteria, facts []DictionaryEntry, known map[DictionaryEntry]struct{}, complete bool) (bool, error) {
	if len(facts) == 0 && !complete {
		return false, ErrInvalidFacts
	}
	match := false
	for _, fact := range facts {
		// All is a wildcard criterion, not a classification of a concrete event.
		if isAllEvents(fact) {
			return false, ErrInvalidFacts
		}
		if _, exists := known[fact]; !exists {
			return false, ErrInvalidFacts
		}
		if slices.Contains(criteria, fact) {
			match = true
		}
	}
	return match, nil
}
