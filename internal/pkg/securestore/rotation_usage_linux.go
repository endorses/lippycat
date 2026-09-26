//go:build linux

package securestore

import (
	"errors"
	"os"
)

func (r *RotationIO) checkUsageKey(ring *Keyring) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.ready(); err != nil {
		return err
	}
	if ring == nil || ring.active == nil || ring.UsageFileName() != r.names[RotationUsage] {
		return errors.New("securestore: rotation usage key does not match its reserved role")
	}
	return nil
}

// InitializeUsage is exclusive and never resets an existing ledger. Only an
// authenticated ledger-uninitialized bootstrap authorizes the caller to use it.
// The caller must durably advance to ledger-required before its first GCM seal.
func (r *RotationIO) InitializeUsage(ring *Keyring, store [16]byte) (out Outcome, result error) {
	out = NotCommitted
	if err := r.checkUsageKey(ring); err != nil {
		return out, err
	}
	if store == [16]byte{} {
		return out, errors.New("securestore: rotation usage requires an authenticated store identity")
	}
	lock, err := r.dir.Lock(r.names[RotationUsage])
	if err != nil {
		return out, err
	}
	defer func() {
		if err := lock.Close(); err != nil {
			result = errors.Join(result, &CommitError{Outcome: out, Op: "close rotation usage initialization lock", Err: err})
		}
	}()
	if _, err := r.dir.FileIdentity(r.names[RotationUsage]); err == nil {
		return out, os.ErrExist
	} else if !errors.Is(err, os.ErrNotExist) {
		return out, err
	}
	if err := r.Prepare(RotationUsage); err != nil {
		return out, err
	}
	return r.Create(RotationUsage, encodeUsage(ring.active, store, 0, 0))
}

// OpenUsage retains the existing authenticated owner and installs transaction I/O
// before returning it. Every later highwater rewrite uses an attributed allocated
// temporary. Missing/invalid ledgers remain fatal; this method never initializes.
// Close Usage before RotationIO. Only a fresh reopened pair may clear a fault.
func (r *RotationIO) OpenUsage(ring *Keyring, expectedStore [16]byte) (*Usage, error) {
	if err := r.checkUsageKey(ring); err != nil {
		return nil, err
	}
	u, err := OpenUsage(r.dir, ring, expectedStore)
	if err != nil {
		return nil, err
	}
	u.mu.Lock()
	u.write = func(name string, data []byte) (Outcome, error) {
		if name != r.names[RotationUsage] || len(data) != usageBytes {
			return NotCommitted, errors.New("securestore: unexpected rotation usage write")
		}
		if err := r.Prepare(RotationUsage); err != nil {
			return NotCommitted, err
		}
		return r.Replace(RotationUsage, data)
	}
	u.mu.Unlock()
	return u, nil
}
