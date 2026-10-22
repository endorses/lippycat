//go:build li

package iripolicy

import (
	"cmp"
	"slices"
)

// CloneObject returns a detached copy of an object's entire definition.
func CloneObject(object Object) Object {
	clone := object
	if object.Policy != nil {
		policy := *object.Policy
		policy.Rules = slices.Clone(object.Policy.Rules)
		clone.Policy = &policy
	}
	if object.Rule != nil {
		rule := *object.Rule
		rule.Criteria = make([]Criterion, len(object.Rule.Criteria))
		for i, criterion := range object.Rule.Criteria {
			rule.Criteria[i] = cloneCriterion(criterion)
		}
		clone.Rule = &rule
	}
	return clone
}

// CloneObjects returns detached copies of all objects, preserving input order.
func CloneObjects(objects []Object) []Object {
	if objects == nil {
		return nil
	}
	clones := make([]Object, len(objects))
	for i, object := range objects {
		clones[i] = CloneObject(object)
	}
	return clones
}

func cloneCriterion(criterion Criterion) Criterion {
	clone := Criterion{
		NFTypes: slices.Clone(criterion.NFTypes),
		Events:  slices.Clone(criterion.Events),
	}
	if criterion.HandoverFormat != nil {
		entry := *criterion.HandoverFormat
		clone.HandoverFormat = &entry
	}
	return clone
}

// EqualObjects compares definitions, ignoring administrative generations and
// irrelevant ordering of AND criteria, OR entries, and ordered rule references.
// It does not modify either input. IDs and policy names remain significant.
func EqualObjects(a, b Object) bool {
	if a.ID != b.ID || (a.Policy == nil) != (b.Policy == nil) || (a.Rule == nil) != (b.Rule == nil) {
		return false
	}
	if a.Policy != nil {
		if a.Policy.Name != b.Policy.Name {
			return false
		}
		left, right := slices.Clone(a.Policy.Rules), slices.Clone(b.Policy.Rules)
		slices.SortFunc(left, compareReferences)
		slices.SortFunc(right, compareReferences)
		if !slices.Equal(left, right) {
			return false
		}
	}
	if a.Rule != nil {
		if a.Rule.Action != b.Rule.Action {
			return false
		}
		left, right := canonicalCriteria(a.Rule.Criteria), canonicalCriteria(b.Rule.Criteria)
		if !slices.EqualFunc(left, right, func(a, b Criterion) bool { return compareCriteria(a, b) == 0 }) {
			return false
		}
	}
	return true
}

func canonicalCriteria(criteria []Criterion) []Criterion {
	canonical := make([]Criterion, len(criteria))
	for i, criterion := range criteria {
		canonical[i] = cloneCriterion(criterion)
		slices.SortFunc(canonical[i].NFTypes, compareEntries)
		slices.SortFunc(canonical[i].Events, compareEntries)
	}
	slices.SortFunc(canonical, compareCriteria)
	return canonical
}

func compareReferences(a, b RuleReference) int {
	if order := cmp.Compare(a.Order, b.Order); order != 0 {
		return order
	}
	return slices.Compare(a.ObjectID[:], b.ObjectID[:])
}

func compareEntries(a, b DictionaryEntry) int {
	if order := cmp.Compare(a.Owner, b.Owner); order != 0 {
		return order
	}
	if order := cmp.Compare(a.Name, b.Name); order != 0 {
		return order
	}
	return cmp.Compare(a.Value, b.Value)
}

func compareCriteria(a, b Criterion) int {
	if order := slices.CompareFunc(a.NFTypes, b.NFTypes, compareEntries); order != 0 {
		return order
	}
	if order := slices.CompareFunc(a.Events, b.Events, compareEntries); order != 0 {
		return order
	}
	if a.HandoverFormat == nil {
		if b.HandoverFormat == nil {
			return 0
		}
		return -1
	}
	if b.HandoverFormat == nil {
		return 1
	}
	return compareEntries(*a.HandoverFormat, *b.HandoverFormat)
}
