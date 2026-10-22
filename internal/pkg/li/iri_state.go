//go:build li

package li

import (
	"github.com/endorses/lippycat/internal/pkg/li/iripolicy"
)

// Stored dictionaries are data, not the live capability profile. Validate their
// structure independently so a changed deployment profile cannot arm old data.
func validateStateIRIGraph(objects []iripolicy.Object, b *stateBudget) error {
	if len(objects) > 4096 {
		return stateError("IRI policy object limit")
	}
	profile := iripolicy.Profile{}
	nf, events, formats := map[iripolicy.DictionaryEntry]bool{}, map[iripolicy.DictionaryEntry]bool{}, map[iripolicy.DictionaryEntry]bool{}
	for _, object := range objects {
		if object.Generation == 0 {
			return stateError("IRI policy object generation")
		}
		if err := b.charge(96); err != nil {
			return err
		}
		if object.Policy != nil {
			if err := stateStrings(b, object.Policy.Name); err != nil {
				return err
			}
			if err := b.charge(48 * len(object.Policy.Rules)); err != nil {
				return err
			}
		}
		if object.Rule == nil {
			continue
		}
		for _, criterion := range object.Rule.Criteria {
			if err := b.charge(96); err != nil {
				return err
			}
			for _, entry := range criterion.NFTypes {
				if !nf[entry] {
					profile.NFTypes = append(profile.NFTypes, entry)
					nf[entry] = true
				}
				if err := stateStrings(b, entry.Owner, entry.Name, entry.Value); err != nil {
					return err
				}
			}
			for _, entry := range criterion.Events {
				if !(entry.Owner == "ETSI" && entry.Name == "IRIEvents" && entry.Value == "All") && !events[entry] {
					profile.Events = append(profile.Events, entry)
					events[entry] = true
				}
				if err := stateStrings(b, entry.Owner, entry.Name, entry.Value); err != nil {
					return err
				}
			}
			if entry := criterion.HandoverFormat; entry != nil {
				if !formats[*entry] {
					profile.HandoverFormats = append(profile.HandoverFormats, *entry)
					formats[*entry] = true
				}
				if err := stateStrings(b, entry.Owner, entry.Name, entry.Value); err != nil {
					return err
				}
			}
			b.destinations += len(criterion.NFTypes) + len(criterion.Events)
			if b.destinations > maxStateTotalReferences {
				return stateError("total IRI policy reference limit")
			}
		}
	}
	if err := iripolicy.ValidateObjects(objects, profile, iripolicy.Limits{}); err != nil {
		return stateError("IRI policy graph")
	}
	return nil
}
