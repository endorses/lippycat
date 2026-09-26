package securestore

import (
	"errors"
	"sort"
)

// SourceRingBinding binds every loaded source key and the explicit legacy
// selection under the fresh output key. It is an opaque operation binding,
// never a diagnostic fingerprint or a substitute for authenticating source data.
func (target *Keyring) SourceRingBinding(source *Keyring) ([32]byte, error) {
	var out [32]byte
	if target == nil || target.active == nil || len(target.keys) != 1 || target.legacy != nil || source == nil || source.active == nil || len(source.keys) == 0 || len(source.keys) > 1+MaxPriorKeys {
		return out, errors.New("securestore: invalid journal rewrite keys")
	}
	if err := CheckIndependent(source, target); err != nil {
		return out, err
	}
	if _, exists := source.keys[target.active.id]; exists {
		return out, errors.New("securestore: journal rewrite requires a fresh key ID")
	}
	ids := make([]string, 0, len(source.keys))
	for id := range source.keys {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	b := make([]byte, 0, 4+2*MaxKeyIDBytes+len(ids)*(2+MaxKeyIDBytes+KeyBytes))
	b = appendRotationString(b, source.active.id)
	legacyID := ""
	if source.legacy != nil {
		legacyID = source.legacy.id
	}
	b = appendRotationString(b, legacyID)
	for _, id := range ids {
		b = appendRotationString(b, id)
		b = append(b, source.keys[id].raw[:]...)
	}
	defer clear(b)
	copy(out[:], target.active.mac("lippycat/securestore/journal-rewrite/source-ring/v1\x00", b))
	return out, nil
}
