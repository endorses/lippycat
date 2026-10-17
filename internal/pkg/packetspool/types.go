// Package packetspool owns bounded, restart-persistent raw packet custody.
// Reading never retires data. Callers authenticate receipts before applying them.
package packetspool

import (
	"errors"
	"fmt"
	"time"
	"unicode/utf8"

	data "github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/internal/pkg/securestore"
)

type ExhaustionPolicy string

const (
	DropOldest  ExhaustionPolicy = "drop_oldest"
	DropNew     ExhaustionPolicy = "drop_new"
	Private                      = "private"
	Encrypted                    = "encrypted"
	Receiver                     = "receiver"
	Central                      = "central"
	maxPayload                   = 32 << 20
	maxManifest                  = 32 << 20
)

var (
	ErrNotInitialized = errors.New("packet spool requires explicit initialization")
	ErrClosed         = errors.New("packet spool is closed")
	ErrUncertain      = errors.New("packet spool durability is uncertain; reopen required")
	ErrLossCapacity   = errors.New("packet spool loss metadata capacity exhausted; confirm losses before retry")
	ErrIdentity       = errors.New("packet spool identity or receipt binding mismatch")
	ErrReceipt        = errors.New("packet spool receipt exceeds established coverage")
	ErrCleanup        = errors.New("packet spool committed mutation needs cleanup")
)

// Config requires an explicit destination, receipt scope, and protection mode.
// MaxBytes counts encoded active batch files; MaxRecords and MaxRecordBytes
// remain finite even when MaxBytes or MaxAge is zero (unlimited).
type Config struct {
	Directory, SourceID, DestinationID, AckScope, CaptureEpoch string
	Protection                                                 string
	Keys                                                       *securestore.Keyring
	MaxBytes, MaxRecordBytes, MaxReadBytes                     uint64
	MaxAge                                                     time.Duration
	MaxRecords, MaxLossRanges                                  int
	Policy                                                     ExhaustionPolicy
	Clock                                                      func() time.Time
	fs                                                         *fileOps
}

func (c Config) Validate() (Config, error) {
	if c.Directory == "" || !validID(c.SourceID) || !validID(c.DestinationID) {
		return Config{}, fmt.Errorf("packet spool requires a directory and bounded source/destination identities")
	}
	if c.AckScope != Receiver && c.AckScope != Central {
		return Config{}, fmt.Errorf("packet spool ack scope must be receiver or central")
	}
	if c.Protection != Private && c.Protection != Encrypted {
		return Config{}, fmt.Errorf("packet spool protection must explicitly be private or encrypted")
	}
	if (c.Protection == Encrypted) != (c.Keys != nil) {
		return Config{}, fmt.Errorf("encrypted packet spool requires keys; private mode forbids keys")
	}
	if c.CaptureEpoch != "" && !validID(c.CaptureEpoch) {
		return Config{}, ErrIdentity
	}
	if c.MaxRecordBytes == 0 {
		c.MaxRecordBytes = 4 << 20
	}
	if c.MaxRecordBytes > maxPayload {
		return Config{}, fmt.Errorf("packet spool record limit exceeds %d bytes", maxPayload)
	}
	if c.MaxReadBytes == 0 {
		c.MaxReadBytes = max(16<<20, c.MaxRecordBytes)
	}
	if c.MaxReadBytes < c.MaxRecordBytes || c.MaxReadBytes > 128<<20 {
		return Config{}, fmt.Errorf("packet spool retrieval byte bound is invalid")
	}
	if c.MaxRecords == 0 {
		c.MaxRecords = 4096
	}
	if c.MaxLossRanges == 0 {
		c.MaxLossRanges = 4096
	}
	if c.MaxRecords < 1 || c.MaxRecords > 65536 || c.MaxLossRanges < 1 || c.MaxLossRanges > 65536 || c.MaxAge < 0 {
		return Config{}, fmt.Errorf("packet spool resource limits are invalid")
	}
	if c.Policy == "" {
		c.Policy = DropOldest
	}
	if c.Policy != DropOldest && c.Policy != DropNew {
		return Config{}, fmt.Errorf("packet spool exhaustion policy must be drop_oldest or drop_new")
	}
	if c.Clock == nil {
		c.Clock = time.Now
	}
	return c, nil
}

func validID(value string) bool {
	return value != "" && len(value) <= 256 && utf8.ValidString(value) && !containsNUL(value)
}
func containsNUL(value string) bool {
	for _, r := range value {
		if r == 0 {
			return true
		}
	}
	return false
}

type Identity struct {
	SourceID      string `json:"source"`
	SessionID     string `json:"session"`
	CaptureEpoch  string `json:"epoch"`
	DestinationID string `json:"destination"`
	AckScope      string `json:"scope"`
	Protection    string `json:"protection"`
}

type LossRange struct {
	First, Last uint64
	Reason      string
	Confirmed   bool
}
type LossCoverage struct {
	Version uint64
	Ranges  []LossRange
}
type Result struct {
	Batch                      *data.PacketBatch
	Sequence                   uint64
	Stored, Dropped, Committed bool
	Losses                     LossCoverage
}
type Status struct {
	Identity                      Identity
	PendingRecords, PendingLosses int
	LogicalBytes                  uint64
	LastSequence, AckedSequence   uint64
	DroppedRecords                uint64
	OldestAge                     time.Duration
	DurabilityUncertain, Closed   bool
	CleanupError                  string
}

type record struct {
	Sequence uint64
	Created  int64
	Size     uint64
	Digest   string
}
type state struct {
	Version                                  uint32
	Identity                                 Identity
	LastSequence, AckedSequence, LossVersion uint64
	Records                                  []record
	Losses                                   []LossRange
}

// fileOps provides package-local publication/cleanup fault seams. Production
// operations retain securestore's descriptor-relative ownership protections.
type fileOps struct {
	create  func(string, []byte) (securestore.Outcome, error)
	replace func(string, []byte) (securestore.Outcome, error)
	remove  func(string) (securestore.Outcome, error)
	sync    func() error
}
