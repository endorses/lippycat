//go:build linux

package securestore

import (
	"encoding/binary"
	"errors"
	"math"
	"strings"

	"golang.org/x/sys/unix"
)

func rotationEnvelopeKeyID(b []byte) string {
	if len(b) < fixedHeaderBytes {
		return ""
	}
	n := int(binary.BigEndian.Uint16(b[8:10]))
	if n < 1 || n > MaxKeyIDBytes || len(b) < fixedHeaderBytes+n {
		return ""
	}
	return string(b[fixedHeaderBytes : fixedHeaderBytes+n])
}
func (r *snapshotRotation) inventoryReport() error {
	r.result.InventoryComplete = true
	add := func(kind, id string, n int64, known bool) {
		for i := range r.result.Artifacts {
			a := &r.result.Artifacts[i]
			if a.Kind == kind && a.KeyID == id && a.DependencyKnown == known {
				a.Count++
				a.AllocatedBytes += n
				return
			}
		}
		r.result.Artifacts = append(r.result.Artifacts, RotationArtifact{Kind: kind, KeyID: id, Count: 1, AllocatedBytes: n, DependencyKnown: known})
	}
	type knownArtifact struct{ kind, key string }
	known := map[string]knownArtifact{
		r.destinationName: {"snapshot", r.options.NewKeys.ActiveID()}, r.names[RotationBootstrapUninitialized]: {"rotation-bootstrap", r.options.NewKeys.ActiveID()}, r.names[RotationPlanned]: {"rotation-progress", r.options.NewKeys.ActiveID()}, r.options.NewKeys.UsageFileName(): {"usage-history", r.options.NewKeys.ActiveID()}, r.options.SourceKeys.UsageFileName(): {"usage-history", r.options.SourceKeys.ActiveID()},
	}
	if !r.options.InPlace {
		known[r.sourceName] = knownArtifact{"snapshot", rotationEnvelopeKeyID(r.sourceCipher)}
	}
	for _, ring := range []*Keyring{r.options.SourceKeys, r.options.NewKeys} {
		for id, key := range ring.keys {
			name := usageName(key)
			if _, exists := known[name]; exists {
				continue
			}
			b, err := r.readOptional(name, usageBytes)
			if err != nil {
				return err
			}
			if b == nil {
				continue
			}
			store, _, _, err := decodeUsage(key, b)
			if err != nil || store != r.store {
				continue
			}
			known[name] = knownArtifact{"usage-history", id}
		}
	}
	locks := map[string]bool{}
	for _, o := range r.locks {
		locks[rotationLockName(o.name)] = true
	}
	entries := 0
	err := r.dir.WalkEntries(func(name string) error {
		entries++
		if entries > rotationInventoryMax {
			return errors.New("securestore: rotation report inventory limit exceeded")
		}
		if locks[name] {
			return nil
		}
		r.dir.mu.Lock()
		var st unix.Stat_t
		err := unix.Fstatat(int(r.dir.file.Fd()), name, &st, unix.AT_SYMLINK_NOFOLLOW)
		r.dir.mu.Unlock()
		if err != nil {
			return err
		}
		n := int64(0)
		if st.Mode&unix.S_IFMT == unix.S_IFREG && st.Blocks >= 0 && st.Blocks <= math.MaxInt64/512 {
			n = st.Blocks * 512
		}
		if entry, ok := known[name]; ok {
			if err := r.keyAliases(name); err != nil {
				return err
			}
			add(entry.kind, entry.key, n, true)
			if entry.kind == "usage-history" {
				r.result.HistoricalUsageBytes += n
			}
			if name == r.sourceName && !r.options.InPlace {
				r.result.OldSourceBytes = n
			}
			return nil
		}
		// Only recognized scope is attributed. Unknown files/temporaries are never
		// silently counted as retired-key-free or removed, and no paths are printed.
		kind := "unclassified"
		if strings.HasPrefix(name, ".securestore-") {
			kind = "unowned-temporary-or-lock"
		}
		add(kind, "", n, false)
		r.result.InventoryComplete = false
		return nil
	})
	if err != nil {
		r.result.InventoryComplete = false
		return err
	}
	n, err := r.workspace.AllocatedBytes()
	if err != nil {
		return err
	}
	r.result.WorkingAllocatedBytes = n
	return nil
}
