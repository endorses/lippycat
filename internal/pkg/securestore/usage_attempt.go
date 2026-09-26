package securestore

import (
	"errors"
	"os"
)

// ReserveAttempt reserves one finite offline attempt through an already
// allocated ledger writer. The owner must authenticate its bootstrap first.
// Counters consumed by a prior attempt remain consumed, including after restart.
// The exact fence is independent of rounded durable highwaters; exceeding it
// cannot allocate another ledger slot or silently extend the attempt.
func (u *Usage) ReserveAttempt(seals, blocks uint64, write func(string, []byte) (Outcome, error)) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.closed || u.fault != nil || u.finiteAttempt || (u.beforeReserve != nil && !u.attemptWorkspace) || write == nil {
		return errors.Join(ErrUsageFault, u.fault)
	}
	if seals == 0 || blocks == 0 || u.usedSeals >= MaxKeyInvocations*9/10 || u.usedBlocks >= MaxKeyBlocks*9/10 || seals > MaxKeyInvocations*9/10-u.usedSeals || blocks > MaxKeyBlocks*9/10-u.usedBlocks {
		return ErrKeyExhausted
	}
	endSeals, endBlocks := u.usedSeals+seals, u.usedBlocks+blocks
	reservedSeals := max(u.reservedSeals, roundReservation(endSeals, invocationReservation, MaxKeyInvocations))
	reservedBlocks := max(u.reservedBlocks, roundReservation(endBlocks, blockReservation, MaxKeyBlocks))
	out, err := write(u.name, encodeUsage(u.key, u.store, reservedSeals, reservedBlocks))
	if err != nil || out != Committed {
		if err == nil {
			err = errors.New("offline usage reservation was not committed")
		}
		u.fault = &UsageError{ReservationOutcome: out, Err: err}
		if out == NotCommitted {
			reservedSeals, reservedBlocks = u.reservedSeals, u.reservedBlocks
		}
		u.publishUsage(out, reservedSeals, reservedBlocks)
		return errors.Join(ErrUsageFault, u.fault)
	}
	u.reservedSeals, u.reservedBlocks = reservedSeals, reservedBlocks
	u.finiteAttempt = true
	u.beforeReserve = nil
	u.finiteSeals, u.finiteBlocks = endSeals, endBlocks
	u.publishUsage(Committed, reservedSeals, reservedBlocks)
	return nil
}

// InitializeUsageWithWriter is explicit offline initialization through a
// caller-preallocated no-clobber writer. It never replaces an existing ledger.
// The caller must authenticate the ledger-uninitialized bootstrap, retain the
// owning journal lock, and advance durably to ledger-required before any seal.
func InitializeUsageWithWriter(dir *Dir, ring *Keyring, store [16]byte, write func(string, []byte) (Outcome, error)) (out Outcome, result error) {
	if dir == nil || ring == nil || ring.active == nil || store == [16]byte{} || write == nil {
		return NotCommitted, errors.New("offline usage initialization requires ownership, key and writer")
	}
	name := ring.UsageFileName()
	lock, err := dir.Lock(name)
	if err != nil {
		return NotCommitted, err
	}
	defer func() {
		if err := lock.Close(); err != nil {
			result = errors.Join(result, &CommitError{Outcome: out, Op: "close offline usage initialization", Err: err})
		}
	}()
	if _, err := dir.FileIdentity(name); err == nil {
		return NotCommitted, os.ErrExist
	} else if !errors.Is(err, os.ErrNotExist) {
		return NotCommitted, err
	}
	return write(name, encodeUsage(ring.active, store, 0, 0))
}
