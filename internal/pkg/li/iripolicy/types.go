//go:build li

// Package iripolicy validates and evaluates selective IRI delivery policies from
// ETSI TS 103 120. It is independent of the provisioning and handover encodings.
package iripolicy

import (
	"errors"

	"github.com/google/uuid"
)

// DictionaryEntry identifies one exact value in an ETSI or national dictionary.
// Strings are case-sensitive and are never normalized during evaluation.
type DictionaryEntry struct {
	Owner string
	Name  string
	Value string
}

// Criterion selects exactly one criterion kind. Values within a kind are ORed;
// the criteria belonging to a rule are ANDed.
type Criterion struct {
	NFTypes        []DictionaryEntry
	Events         []DictionaryEntry
	HandoverFormat *DictionaryEntry
}

// Rule describes the criteria and delivery action of an IRI rule object.
// At least one criterion is required; ETSI IRIEvents/All is an explicit catch-all.
type Rule struct {
	Criteria []Criterion
	Action   DictionaryEntry
}

// RuleReference assigns a positive evaluation order to a rule object.
type RuleReference struct {
	Order    uint64
	ObjectID uuid.UUID
}

// Policy identifies a nonempty ordered collection of rule references.
type Policy struct {
	Name  string
	Rules []RuleReference
}

// Object is an independently provisioned policy or rule. Exactly one of Policy
// and Rule must be set. Generation is supplied by the administrative state owner.
type Object struct {
	ID         uuid.UUID
	Generation uint64
	Policy     *Policy
	Rule       *Rule
}

// Profile declares dictionary entries for which the NE can supply reliable
// runtime facts. Declaring an entry does not create an ETSI dictionary value.
// ETSI IRIEvents/All is supported without being declared in a profile.
type Profile struct {
	NFTypes         []DictionaryEntry
	Events          []DictionaryEntry
	HandoverFormats []DictionaryEntry
}

// Facts describes one candidate IRI delivery. Missing facts in a criterion family
// used by a policy are an evaluation error, so they cannot bypass suppression.
type Facts struct {
	NFTypes        []DictionaryEntry
	Events         []DictionaryEntry
	HandoverFormat *DictionaryEntry
	// Known flags distinguish reliable absence from unavailable classification.
	// Nonempty, validated entries also establish knowledge of that family.
	NFTypesKnown bool
	EventsKnown  bool
}

// Limits bounds policy state and compilation. Zero fields use the defaults;
// negative fields are invalid. These limits are resource bounds, not performance
// acceptance targets.
type Limits struct {
	MaxObjects             int
	MaxPolicyReferences    int
	MaxRulesPerPolicy      int
	MaxCriteriaPerRule     int
	MaxEntriesPerCriterion int
}

// DefaultLimits returns the package resource bounds.
func DefaultLimits() Limits {
	return Limits{
		MaxObjects:             4096,
		MaxPolicyReferences:    256,
		MaxRulesPerPolicy:      256,
		MaxCriteriaPerRule:     64,
		MaxEntriesPerCriterion: 256,
	}
}

// Errors identify structural validation failures without including policy names,
// dictionary values, or intercepted content in their messages.
var (
	ErrInvalidGeneration  = errors.New("invalid IRI policy source generation")
	ErrInvalidObject      = errors.New("invalid IRI policy object")
	ErrDuplicateObjectID  = errors.New("duplicate IRI policy object identifier")
	ErrMissingObject      = errors.New("missing IRI policy object")
	ErrWrongObjectKind    = errors.New("wrong IRI policy object kind")
	ErrDuplicateReference = errors.New("duplicate IRI policy reference")
	ErrInvalidOrder       = errors.New("invalid IRI rule order")
	ErrUnsupportedEntry   = errors.New("unsupported IRI dictionary entry")
	ErrInvalidAction      = errors.New("invalid IRI rule action")
	ErrInvalidProfile     = errors.New("invalid IRI policy profile")
	ErrInvalidFacts       = errors.New("invalid IRI policy facts")
	ErrLimitExceeded      = errors.New("IRI policy resource limit exceeded")
	ErrInvalidLimits      = errors.New("invalid IRI policy resource limits")
)
