package securestore

import (
	"crypto/hmac"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
)

const (
	MaxKeyInvocations     uint64 = 1 << 32
	MaxKeyBlocks          uint64 = 1 << 40
	invocationReservation uint64 = 4096
	blockReservation      uint64 = 1 << 20
	usageBytes                   = 72
	usageMACDomain               = "lippycat/securestore/usage/v1\x00"
)

var (
	ErrKeyExhausted = errors.New("encryption key usage limit reached; offline rotation required")
	ErrUsageFault   = errors.New("encryption usage ledger faulted or closed; restart and reconcile storage")
)

// UsageError reports an auxiliary usage-ledger failure, not a commitment of the
// object the caller intended to encrypt. ReservationOutcome remains available
// even though Writer.Seal correctly reports that no object was committed.
type UsageError struct {
	ReservationOutcome Outcome
	Err                error
}

func (e *UsageError) Error() string { return fmt.Sprintf("reserve encryption key usage: %v", e.Err) }
func (e *UsageError) Unwrap() error { return e.Err }

// UsageStats includes reservations lost after restart. Ordinary writes stop at
// 90%; the final 10% remains available for required control records.
type UsageStats struct {
	Invocations, Blocks uint64
	RotateRecommended   bool
	Faulted             bool
}

// Usage is a locked, restart-persistent high-watermark allocator. Reservations
// are authenticated with HMAC rather than GCM to avoid recursive nonce usage.
// Never delete a ledger or reuse its key in an independently initialized store.
type Usage struct {
	mu                            sync.Mutex
	key                           *key
	store                         [16]byte
	dir                           *Dir
	name                          string
	lock                          *Lock
	usedSeals, usedBlocks         uint64
	reservedSeals, reservedBlocks uint64
	fault                         error
	closed                        bool
	write                         func(string, []byte) (Outcome, error)
}

func usageName(k *key) string {
	// Independent of operator key IDs: renaming a key cannot reset accounting.
	return ".usage-" + hex.EncodeToString(k.mac("lippycat/securestore/usage-name/v1\x00", nil))
}

func encodeUsage(k *key, store [16]byte, seals, blocks uint64) []byte {
	b := make([]byte, usageBytes)
	copy(b, "LCUS")
	b[4] = 1
	copy(b[8:24], store[:])
	binary.BigEndian.PutUint64(b[24:32], seals)
	binary.BigEndian.PutUint64(b[32:40], blocks)
	copy(b[40:], k.mac(usageMACDomain, b[:40]))
	return b
}

func decodeUsage(k *key, data []byte) ([16]byte, uint64, uint64, error) {
	var store [16]byte
	if len(data) != usageBytes || string(data[:4]) != "LCUS" || data[4] != 1 || data[5] != 0 || data[6] != 0 || data[7] != 0 {
		return store, 0, 0, errors.New("invalid encryption usage ledger")
	}
	if !hmac.Equal(data[40:], k.mac(usageMACDomain, data[:40])) {
		return store, 0, 0, ErrAuthentication
	}
	copy(store[:], data[8:24])
	seals, blocks := binary.BigEndian.Uint64(data[24:32]), binary.BigEndian.Uint64(data[32:40])
	if store == [16]byte{} || seals > MaxKeyInvocations || blocks > MaxKeyBlocks {
		return store, 0, 0, errors.New("invalid encryption usage ledger bounds")
	}
	return store, seals, blocks, nil
}

// InitializeUsage is for explicit offline initialization/rotation ONLY. Store
// identity must be fresh on initialization and preserved during rotation. It
// refuses an existing ledger, even if the counter is zero.
func InitializeUsage(dir *Dir, ring *Keyring, store [16]byte) (out Outcome, result error) {
	if dir == nil || ring == nil || store == [16]byte{} {
		return NotCommitted, errors.New("usage initialization requires a directory, key, and nonzero store identity")
	}
	name := usageName(ring.active)
	lock, err := dir.Lock(name)
	if err != nil {
		return NotCommitted, err
	}
	defer func() {
		if err := lock.Close(); err != nil {
			result = errors.Join(result, &CommitError{Outcome: out, Op: "close usage initialization lock", Err: err})
		}
	}()
	return dir.Create(name, encodeUsage(ring.active, store, 0, 0))
}

// OpenUsage never initializes a missing ledger. A zero expectedStore discovers
// the authenticated store identity for snapshot startup; journal owners can
// supply an already authenticated expected identity instead.
func OpenUsage(dir *Dir, ring *Keyring, expectedStore [16]byte) (u *Usage, result error) {
	if dir == nil || ring == nil {
		return nil, errors.New("usage loading requires a directory and key")
	}
	name := usageName(ring.active)
	lock, err := dir.Lock(name)
	if err != nil {
		return nil, err
	}
	defer func() {
		if result != nil {
			if err := lock.Close(); err != nil {
				result = errors.Join(result, fmt.Errorf("close failed usage lock: %w", err))
			}
		}
	}()
	data, err := dir.Read(name, usageBytes)
	if err != nil {
		return nil, fmt.Errorf("read required encryption usage ledger: %w", err)
	}
	store, seals, blocks, err := decodeUsage(ring.active, data)
	if err != nil {
		return nil, err
	}
	if expectedStore != [16]byte{} && expectedStore != store {
		return nil, ErrBinding
	}
	// All previously reserved values are consumed, including unused reservations
	// from clean shutdown. No shutdown write is needed for nonce safety.
	return &Usage{key: ring.active, store: store, dir: dir, name: name, lock: lock,
		usedSeals: seals, usedBlocks: blocks, reservedSeals: seals, reservedBlocks: blocks,
		write: dir.Replace}, nil
}

func (u *Usage) StoreID() [16]byte { return u.store }

func roundReservation(value, step, limit uint64) uint64 {
	if value > limit-step {
		return limit
	}
	return min((value+step-1)/step*step, limit)
}

func (u *Usage) reserve(blocks uint64, control bool) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.closed || u.fault != nil {
		return errors.Join(ErrUsageFault, u.fault)
	}
	sealsLimit, blocksLimit := MaxKeyInvocations, MaxKeyBlocks
	if !control {
		sealsLimit, blocksLimit = sealsLimit*9/10, blocksLimit*9/10
	}
	if blocks == 0 || u.usedSeals >= sealsLimit || u.usedBlocks >= blocksLimit || blocks > blocksLimit-u.usedBlocks {
		return ErrKeyExhausted
	}
	nextSeals, nextBlocks := u.usedSeals+1, u.usedBlocks+blocks
	if nextSeals > u.reservedSeals || nextBlocks > u.reservedBlocks {
		reservedSeals := max(u.reservedSeals, roundReservation(nextSeals, invocationReservation, sealsLimit))
		reservedBlocks := max(u.reservedBlocks, roundReservation(nextBlocks, blockReservation, blocksLimit))
		outcome, err := u.write(u.name, encodeUsage(u.key, u.store, reservedSeals, reservedBlocks))
		if err != nil || outcome != Committed {
			if err == nil {
				err = errors.New("encryption usage reservation was not committed")
			}
			u.fault = &UsageError{ReservationOutcome: outcome, Err: err}
			return errors.Join(ErrUsageFault, u.fault)
		}
		u.reservedSeals, u.reservedBlocks = reservedSeals, reservedBlocks
	}
	u.usedSeals, u.usedBlocks = nextSeals, nextBlocks
	return nil
}

func (u *Usage) Stats() UsageStats {
	u.mu.Lock()
	defer u.mu.Unlock()
	return UsageStats{Invocations: u.reservedSeals, Blocks: u.reservedBlocks,
		RotateRecommended: u.reservedSeals >= MaxKeyInvocations*3/4 || u.reservedBlocks >= MaxKeyBlocks*3/4,
		Faulted:           u.fault != nil}
}

func (u *Usage) Close() error {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.closed {
		return nil
	}
	u.closed = true
	return u.lock.Close()
}
