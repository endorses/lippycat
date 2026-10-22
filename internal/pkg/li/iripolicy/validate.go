//go:build li

package iripolicy

import (
	"fmt"
	"unicode/utf8"

	"github.com/google/uuid"
)

const (
	nfTypeDictionary   = "NFType"
	eventsDictionary   = "IRIEvents"
	handoverDictionary = "HandoverFormat"
)

// ValidateProfile rejects entries whose meaning cannot be established from the
// ETSI dictionary or an explicitly configured national dictionary. The national
// owner syntax is the ISOCountryCode type defined by ETSI TS 103 280.
func ValidateProfile(profile Profile) error {
	_, err := indexProfile(profile)
	return err
}

type profileIndex struct {
	nfTypes         map[DictionaryEntry]struct{}
	events          map[DictionaryEntry]struct{}
	handoverFormats map[DictionaryEntry]struct{}
}

func indexProfile(profile Profile) (profileIndex, error) {
	var index profileIndex
	families := []struct {
		name    string
		entries []DictionaryEntry
		index   *map[DictionaryEntry]struct{}
	}{
		{nfTypeDictionary, profile.NFTypes, &index.nfTypes},
		{eventsDictionary, profile.Events, &index.events},
		{handoverDictionary, profile.HandoverFormats, &index.handoverFormats},
	}
	for i, family := range families {
		if len(family.entries) > DefaultLimits().MaxObjects {
			return profileIndex{}, fmt.Errorf("%w: family %d: %w", ErrInvalidProfile, i, ErrLimitExceeded)
		}
		entries := make(map[DictionaryEntry]struct{}, len(family.entries))
		for j, entry := range family.entries {
			if !validEntry(entry, family.name) {
				return profileIndex{}, fmt.Errorf("%w: family %d entry %d: %w", ErrInvalidProfile, i, j, ErrUnsupportedEntry)
			}
			if _, exists := entries[entry]; exists {
				return profileIndex{}, fmt.Errorf("%w: family %d entry %d: %w", ErrInvalidProfile, i, j, ErrDuplicateReference)
			}
			entries[entry] = struct{}{}
		}
		*family.index = entries
	}
	return index, nil
}

func validEntry(entry DictionaryEntry, dictionary string) bool {
	if entry.Name != dictionary || !validShortString(entry.Owner) || !validShortString(entry.Value) || entry.Value == "" {
		return false
	}
	if entry.Owner != "ETSI" {
		return len(entry.Owner) == 2 && entry.Owner[0] >= 'A' && entry.Owner[0] <= 'Z' && entry.Owner[1] >= 'A' && entry.Owner[1] <= 'Z'
	}
	switch dictionary {
	case eventsDictionary:
		return entry.Value == "All"
	case handoverDictionary:
		switch entry.Value {
		case "TS102232-2", "TS102232-3", "TS102232-4", "TS102232-5", "TS102232-6", "TS102232-7", "TS103707", "TS103976":
			return true
		}
	}
	return false
}

func validShortString(value string) bool {
	if !utf8.ValidString(value) || utf8.RuneCountInString(value) > 255 {
		return false
	}
	for _, r := range value {
		if r != '\t' && r != '\n' && r != '\r' && (r < 0x20 || r == 0xfffe || r == 0xffff) {
			return false
		}
	}
	return true
}

func resolveLimits(limits Limits) (Limits, error) {
	defaults := DefaultLimits()
	fields := []struct {
		value        *int
		defaultValue int
	}{
		{&limits.MaxObjects, defaults.MaxObjects},
		{&limits.MaxPolicyReferences, defaults.MaxPolicyReferences},
		{&limits.MaxRulesPerPolicy, defaults.MaxRulesPerPolicy},
		{&limits.MaxCriteriaPerRule, defaults.MaxCriteriaPerRule},
		{&limits.MaxEntriesPerCriterion, defaults.MaxEntriesPerCriterion},
	}
	for i, field := range fields {
		if *field.value < 0 {
			return Limits{}, fmt.Errorf("field %d: %w", i, ErrInvalidLimits)
		}
		if *field.value == 0 {
			*field.value = field.defaultValue
		}
	}
	return limits, nil
}

// ValidateObjects validates a detached, complete object graph. Every policy rule
// reference must resolve to a rule in this graph, even for unreferenced policies.
func ValidateObjects(objects []Object, profile Profile, limits Limits) error {
	resolved, err := resolveLimits(limits)
	if err != nil {
		return err
	}
	index, err := indexProfile(profile)
	if err != nil {
		return err
	}
	_, err = indexObjects(objects, index, resolved)
	return err
}

func indexObjects(objects []Object, profile profileIndex, limits Limits) (map[uuid.UUID]Object, error) {
	if len(objects) > limits.MaxObjects {
		return nil, fmt.Errorf("objects: %w", ErrLimitExceeded)
	}
	index := make(map[uuid.UUID]Object, len(objects))
	for i, object := range objects {
		if object.ID == uuid.Nil || (object.Policy == nil) == (object.Rule == nil) {
			return nil, fmt.Errorf("object %d: %w", i, ErrInvalidObject)
		}
		if _, exists := index[object.ID]; exists {
			return nil, fmt.Errorf("object %d: %w", i, ErrDuplicateObjectID)
		}
		if object.Policy != nil {
			if err := validatePolicy(*object.Policy, limits); err != nil {
				return nil, fmt.Errorf("object %d: %w", i, err)
			}
		} else if err := validateRule(*object.Rule, profile, limits); err != nil {
			return nil, fmt.Errorf("object %d: %w", i, err)
		}
		index[object.ID] = object
	}
	for i, object := range objects {
		if object.Policy == nil {
			continue
		}
		for j, reference := range object.Policy.Rules {
			rule, exists := index[reference.ObjectID]
			if !exists {
				return nil, fmt.Errorf("object %d rule reference %d: %w", i, j, ErrMissingObject)
			}
			if rule.Rule == nil {
				return nil, fmt.Errorf("object %d rule reference %d: %w", i, j, ErrWrongObjectKind)
			}
		}
	}
	return index, nil
}

func validatePolicy(policy Policy, limits Limits) error {
	if !validShortString(policy.Name) {
		return fmt.Errorf("policy name: %w", ErrInvalidObject)
	}
	if len(policy.Rules) == 0 {
		return fmt.Errorf("rule references required: %w", ErrInvalidObject)
	}
	if len(policy.Rules) > limits.MaxRulesPerPolicy {
		return fmt.Errorf("rule references: %w", ErrLimitExceeded)
	}
	orders := make(map[uint64]struct{}, len(policy.Rules))
	for i, reference := range policy.Rules {
		if reference.Order == 0 {
			return fmt.Errorf("rule reference %d: %w", i, ErrInvalidOrder)
		}
		if _, exists := orders[reference.Order]; exists {
			return fmt.Errorf("rule reference %d: %w", i, ErrInvalidOrder)
		}
		if reference.ObjectID == uuid.Nil {
			return fmt.Errorf("rule reference %d: %w", i, ErrInvalidObject)
		}
		orders[reference.Order] = struct{}{}
	}
	return nil
}

func validateRule(rule Rule, profile profileIndex, limits Limits) error {
	if rule.Action.Owner != "ETSI" || rule.Action.Name != "IRIAction" || (rule.Action.Value != "Delivered" && rule.Action.Value != "NotDelivered") {
		return ErrInvalidAction
	}
	if len(rule.Criteria) == 0 {
		return fmt.Errorf("criteria required: %w", ErrInvalidObject)
	}
	if len(rule.Criteria) > limits.MaxCriteriaPerRule {
		return fmt.Errorf("criteria: %w", ErrLimitExceeded)
	}
	for i, criterion := range rule.Criteria {
		if err := validateCriterion(criterion, profile, limits); err != nil {
			return fmt.Errorf("criterion %d: %w", i, err)
		}
	}
	return nil
}

func validateCriterion(criterion Criterion, profile profileIndex, limits Limits) error {
	choices := 0
	if criterion.NFTypes != nil {
		choices++
	}
	if criterion.Events != nil {
		choices++
	}
	if criterion.HandoverFormat != nil {
		choices++
	}
	if choices != 1 || (criterion.NFTypes != nil && len(criterion.NFTypes) == 0) || (criterion.Events != nil && len(criterion.Events) == 0) {
		return ErrInvalidObject
	}
	if len(criterion.NFTypes) > limits.MaxEntriesPerCriterion || len(criterion.Events) > limits.MaxEntriesPerCriterion {
		return ErrLimitExceeded
	}
	for i, entry := range criterion.NFTypes {
		if _, exists := profile.nfTypes[entry]; !exists {
			return fmt.Errorf("network function entry %d: %w", i, ErrUnsupportedEntry)
		}
	}
	for i, entry := range criterion.Events {
		if isAllEvents(entry) {
			continue
		}
		if _, exists := profile.events[entry]; !exists {
			return fmt.Errorf("event entry %d: %w", i, ErrUnsupportedEntry)
		}
	}
	if criterion.HandoverFormat != nil {
		if _, exists := profile.handoverFormats[*criterion.HandoverFormat]; !exists {
			return fmt.Errorf("handover format: %w", ErrUnsupportedEntry)
		}
	}
	return nil
}

func isAllEvents(entry DictionaryEntry) bool {
	return entry.Owner == "ETSI" && entry.Name == eventsDictionary && entry.Value == "All"
}
