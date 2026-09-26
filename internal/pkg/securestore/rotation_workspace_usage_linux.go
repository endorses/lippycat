//go:build linux

package securestore

import "errors"

func (w *RotationWorkspace) usageKey(ring *Keyring, store [16]byte) error {
	if ring == nil || ring.active == nil || store == [16]byte{} || ring.UsageFileName() != w.cfg.UsageName {
		return errors.New("securestore: workspace usage key or identity mismatch")
	}
	return nil
}

// InitializeUsage consumes the exclusive zero-ledger stage. Only a fully
// authenticated ledger-uninitialized cut authorizes this call. The caller MUST
// durably publish ledger-required before OpenUsage/Seal. An existing ledger is
// never replaced, copied, or reset, including a zero-valued one.
func (w *RotationWorkspace) InitializeUsage(ring *Keyring, store [16]byte) (Outcome, error) {
	if err := w.usageKey(ring, store); err != nil {
		return NotCommitted, err
	}
	return w.Create(RotationUsageZero, encodeUsage(ring.active, store, 0, 0))
}

// OpenUsage authenticates the required ledger under its already held lock. It
// never creates or reacquires a lock, never initializes, and never allocates a
// replacement inode. All unused durable reservations are consumed on reopen.
// A ready complete remaining workspace and caller-authenticated ledger-required
// bootstrap are prerequisites. Each Seal uses one attempt credit even if it
// shares a durable reservation; SealControl is forbidden for rotation.
func (w *RotationWorkspace) OpenUsage(ring *Keyring, expectedStore [16]byte) (*Usage, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.usable(); err != nil {
		return nil, err
	}
	if err := w.usageKey(ring, expectedStore); err != nil {
		return nil, err
	}
	if !w.reserved || w.usageUsed || w.sealLimit == 0 {
		return nil, errors.New("securestore: workspace usage is not ready or already open")
	}
	data, err := w.dir.Read(w.cfg.UsageName, usageBytes)
	if err != nil {
		return nil, err
	}
	store, seals, blocks, err := decodeUsage(ring.active, data)
	if err != nil {
		return nil, err
	}
	if store != expectedStore {
		return nil, ErrBinding
	}
	// One seal may need at most one highwater write. The complete remaining set
	// supplies one slot per potential seal; unused slots are never refilled.
	stages := make([]RotationStage, 0, 4)
	for s := RotationUsageReservation0; s <= RotationUsageReservation3; s++ {
		if w.slots[s].selected {
			stages = append(stages, s)
		}
	}
	next := 0
	u := &Usage{key: ring.active, store: store, dir: w.dir, name: w.cfg.UsageName, usedSeals: seals, usedBlocks: blocks, reservedSeals: seals, reservedBlocks: blocks}
	for _, owner := range w.cfg.Owners {
		if owner.name == w.cfg.UsageName {
			u.lock = owner
		}
	}
	u.beforeReserve = func(control bool) error {
		w.mu.Lock()
		defer w.mu.Unlock()
		if err := w.usable(); err != nil {
			return err
		}
		if !w.reserved || control || w.seals >= w.sealLimit {
			return errors.New("securestore: finite ordinary rotation seal budget exhausted")
		}
		w.seals++
		return nil
	}
	u.write = func(name string, data []byte) (Outcome, error) {
		if name != w.cfg.UsageName || len(data) != usageBytes || next >= len(stages) {
			return NotCommitted, errors.New("securestore: finite ledger stages exhausted")
		}
		stage := stages[next]
		next++
		return w.Replace(stage, data)
	}
	u.closeBorrowed = func() error { w.mu.Lock(); defer w.mu.Unlock(); w.usageOpen = false; return nil }
	w.usageOpen, w.usageUsed = true, true
	u.publishUsage(Committed, seals, blocks)
	return u, nil
}
