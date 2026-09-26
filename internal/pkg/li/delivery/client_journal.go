//go:build li

package delivery

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/endorses/lippycat/internal/pkg/li"
	"github.com/endorses/lippycat/internal/pkg/li/x2x3"
	"github.com/endorses/lippycat/internal/pkg/securestore"
	"github.com/google/uuid"
)

func (c *Client) initJournal() {
	if err := c.validateStoragePaths(); err != nil {
		c.initErr = err
		return
	}
	x2, x3 := c.config.EffectiveQueueSizes()
	configs := []JournalConfig{
		{PreserveSequences: true, Dir: c.config.X2SpoolDir, KeyFile: c.config.X2SpoolKeyFile, KeyID: c.config.X2SpoolKeyID, LegacyKeyID: c.config.X2SpoolLegacyKeyID, ReadKeys: c.config.X2SpoolReadKeys, ValidateKeys: c.config.X2SpoolValidateKeys, MaxBytes: c.config.X2SpoolMaxBytes, MaxPending: x2, MaxRecords: int(min(c.config.X2SpoolMaxBytes/4096, 1_000_000)), StateIncarnation: c.config.StateIncarnation},
		{PreserveSequences: true, Interface: PDUTypeX3, Dir: c.config.X3SpoolDir, KeyFile: c.config.X3SpoolKeyFile, KeyID: c.config.X3SpoolKeyID, ReadKeys: c.config.X3SpoolReadKeys, ValidateKeys: c.config.X3SpoolValidateKeys, MaxBytes: c.config.X3SpoolMaxBytes, MaxPending: x3, MaxRecords: 2_000_000, StateIncarnation: c.config.StateIncarnation, MaxAge: c.config.X3MaxAge},
	}
	if c.config.X3SpoolDir != "" {
		configs[0].Interface = PDUTypeX2
	}
	var rings []*securestore.Keyring
	for i := range configs {
		cfg := &configs[i]
		if cfg.Dir == "" {
			continue
		}
		id, legacy := cfg.KeyID, cfg.LegacyKeyID
		if id == "" {
			id = journalDefaultKeyID
			if i == 0 && legacy == "" {
				legacy = id
			}
		}
		ring, err := securestore.LoadKeyring(securestore.KeyConfig{Active: securestore.KeyRef{ID: id, File: cfg.KeyFile}, Prior: cfg.ReadKeys, LegacyID: legacy})
		if err == nil && cfg.ValidateKeys != nil {
			err = cfg.ValidateKeys(ring)
		}
		if err != nil {
			c.initErr = err
			return
		}
		cfg.Keys = ring
		cfg.ValidateKeys = nil // validated once above against the immutable owner ring
		rings = append(rings, ring)
	}
	if err := securestore.CheckIndependent(rings...); err != nil {
		c.initErr = err
		return
	}
	// Authenticate every existing owner before either interface may repair,
	// reserve usage, initialize fresh storage, or start runtime workers.
	prepared, err := PrepareJournals(configs)
	if err != nil {
		c.initErr = err
		return
	}
	for i, owner := range prepared {
		if owner == nil {
			continue
		}
		j, err := owner.Activate()
		if err == nil && j.ReadOnly() {
			err = errors.Join(ErrJournalMigrationRequired, j.Close())
			j = nil
		}
		if err != nil {
			for _, pending := range prepared {
				if pending != nil {
					err = errors.Join(err, pending.Close())
				}
			}
			for _, opened := range c.journals() {
				err = errors.Join(err, opened.Close())
			}
			c.journal, c.x2Journal, c.x3Journal = nil, nil, nil
			c.initErr = err
			return
		}
		if i == 0 {
			c.x2Journal = j
			c.journal = j
		} else {
			c.x3Journal = j
		}
	}
	if c.x2Journal != nil && c.config.X2SpoolReplayPolicy == "purge" {
		if err := c.PurgeHeldX2(); err != nil {
			for _, j := range c.journals() {
				err = errors.Join(err, j.Close())
			}
			c.initErr = err
			c.journal, c.x2Journal, c.x3Journal = nil, nil, nil
		}
	}
	if c.x3Journal != nil && c.config.X3SpoolReplayPolicy == "purge" {
		if err := c.PurgeHeldX3(); err != nil {
			for _, j := range c.journals() {
				err = errors.Join(err, j.Close())
			}
			c.initErr = err
			c.journal, c.x2Journal, c.x3Journal = nil, nil, nil
		}
	}

}
func (c *Client) journals() []*Journal {
	var out []*Journal
	if c.x2Journal != nil {
		out = append(out, c.x2Journal)
	} else if c.journal != nil {
		out = append(out, c.journal)
	}
	if c.x3Journal != nil {
		out = append(out, c.x3Journal)
	}
	return out
}
func (c *Client) journalFor(t PDUType) *Journal {
	if t == PDUTypeX3 {
		return c.x3Journal
	}
	if c.x2Journal != nil {
		return c.x2Journal
	}
	return c.journal
}
func (c *Client) X3JournalStats() JournalStats {
	if c.x3Journal == nil {
		return JournalStats{}
	}
	return c.x3Journal.Stats()
}
func (c *Client) FlushPersistence(ctx context.Context) error {
	for _, j := range c.journals() {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := j.Flush(); err != nil {
			return err
		}
	}
	return ctx.Err()
}
func (c *Client) InitializationError() error { return c.initErr }
func (c *Client) JournalStats() JournalStats {
	if c.journal == nil {
		return JournalStats{}
	}
	return c.journal.Stats()
}
func (c *Client) persistItem(q *destinationQueue, item *deliveryItem) error {
	if c.initErr != nil {
		return c.initErr
	}
	j := c.journalFor(item.pduType)
	if j == nil {
		return nil
	}
	if item.metadata.TaskGeneration == 0 || item.metadata.DestinationGeneration == 0 {
		return fmt.Errorf("persistent delivery requires nonzero lifecycle generations")
	}
	if j.segments == nil && j.HoldsDestination(q.did) {
		return fmt.Errorf("journal replay awaits authorization")
	}
	m := item.metadata
	if item.pduType == PDUTypeX3 {
		if m.StateIncarnation == uuid.Nil || m.StateIncarnation != c.config.StateIncarnation || m.Deadline.IsZero() || !time.Now().Before(m.Deadline) {
			return fmt.Errorf("persistent X3 requires current state and unexpired deadline")
		}
		if !c.itemEligible(q.did, item, false) {
			return fmt.Errorf("X3 authorization revoked")
		}
	}
	admit := func(r JournalRecord, cb func(uint64, error)) (uint64, error) { return j.admit(r, cb, false) }
	if item.journalAdmission != nil {
		admit = item.journalAdmission.Admit
	}
	_, err := admit(JournalRecord{Interface: item.pduType, DID: q.did, XID: item.xid, TaskGeneration: m.TaskGeneration, DestinationGeneration: m.DestinationGeneration, CallGeneration: m.CallGeneration, CallID: m.CallID, CallIncarnation: m.CallIncarnation, StateIncarnation: m.StateIncarnation, JournalUUID: j.UUID(), Deadline: m.Deadline, Provenance: m.Provenance, AdmittedAt: m.AdmittedAt, CapturedAt: m.CapturedAt, Data: item.data}, func(id uint64, err error) {
		if err != nil {
			reason := "persistence_failed"
			if errors.Is(err, ErrPersistenceUncertain) {
				reason = "persistence_uncertain"
			}
			if item.detached {
				c.recordTerminalDrop(q.did, q, item, reason)
			} else {
				c.removeItem(q, item, reason)
			}
			return
		}
		item.journalID.Store(id)
		item.durableAt = time.Now()
		item.persisted.Store(true)
		if item.pduType == PDUTypeX3 && (item.terminal.Load() || !c.itemEligible(q.did, item, false)) {
			if !item.metadata.Deadline.IsZero() && !time.Now().Before(item.metadata.Deadline) {
				err = j.Expire(id)
			} else {
				err = j.Complete(id)
			}
			if err != nil {
				j.Hold(id)
			}
			if item.detached {
				c.recordTerminalDrop(q.did, q, item, "lifecycle_suppressed")
			} else {
				c.removeItem(q, item, "lifecycle_suppressed")
			}
			return
		}
		if item.detached {
			c.publishLiveBacklog(j, q, item.pduType, id)
			if item.terminal.CompareAndSwap(false, true) {
				item.payload.release()
			}
			return
		}
		q.mu.Lock()
		stopped, reason := q.stopped, q.stopReason
		q.mu.Unlock()
		if stopped {
			c.dropDestinationQueue(q, reason)
		}
		q.signal()
	})
	return err
}
func (c *Client) RestoreJournalSequences(s *x2x3.Sequencer) error {
	if c.initErr != nil {
		return c.initErr
	}
	for _, j := range c.journals() {
		if err := j.VisitSequences(s.RestoreCheckpoint); err != nil {
			return err
		}
	}
	if c.journal == nil {
		return nil
	}
	return c.journal.VisitHeld(func(r JournalRecord) error {
		cp, err := x2x3.X2SequenceCheckpoint(r.Data)
		if err != nil {
			return err
		}
		if err := validateSequenceIdentity(cp.Context); err != nil {
			return err
		}
		return s.RestoreCheckpoint(cp)
	})
}

// ReplayHeldX2 requires an explicit control-plane authorization for every record.
// The caller must compare task and destination generations with ADMF-authorized
// identities. UUID equality alone is insufficient. Returning false leaves it held.
// Calls must be serialized with administrative purge and new producer activation.
func (c *Client) ReplayHeldX2(authorize func(JournalRecord) bool) error {
	if c.journal == nil {
		return nil
	}
	if authorize == nil {
		return fmt.Errorf("X2 replay authorization required")
	}
	c.journal.controlMu.Lock()
	defer c.journal.controlMu.Unlock()
	blocked := make(map[uuid.UUID]bool)
	var approved []uint64
	if err := c.journal.VisitHeld(func(r JournalRecord) error {
		if blocked[r.DID] || !authorize(r) {
			blocked[r.DID] = true
			return nil
		}
		if r.TaskGeneration == 0 || r.DestinationGeneration == 0 {
			return fmt.Errorf("X2 replay requires nonzero lifecycle generations")
		}
		dest, err := c.manager.GetDestination(r.DID)
		if err != nil {
			return err
		}
		if li.DestinationDeliveryGeneration(dest) != r.DestinationGeneration {
			return fmt.Errorf("replay destination generation changed")
		}
		if !destinationAcceptsPDU(dest, PDUTypeX2) {
			return fmt.Errorf("destination does not accept X2")
		}
		approved = append(approved, r.ID)
		return nil
	}); err != nil {
		return err
	}
	c.journal.mu.Lock()
	for _, id := range approved {
		if e := c.journal.entries[id]; e != nil && e.held && !e.authorized {
			c.journal.stats.ReplayPending++
			e.authorized = true
		}
	}
	c.journal.replayRevision++
	c.journal.mu.Unlock()
	c.admissionMu.Lock()
	defer c.admissionMu.Unlock()
	if c.stopped.Load() {
		return ErrClientStopped
	}
	if !c.journal.replayStarted {
		c.journal.replayStarted = true
		c.wg.Add(1)
		go c.replayJournal()
	}
	return nil
}

// PurgeHeldX2 explicitly discards recovered product and durably checkpoints each
// deletion. It is a control-plane operation and can perform filesystem I/O.
func (c *Client) PurgeHeldX2() error {
	if c.journal == nil {
		return nil
	}
	c.journal.controlMu.Lock()
	defer c.journal.controlMu.Unlock()
	return c.journal.VisitHeld(func(r JournalRecord) error {
		if err := c.journal.Purge(r.ID); err != nil {
			return err
		}
		// Purging historical product must not reserve a delivery queue for a
		// destination that may no longer exist. Aggregate accounting survives
		// removal; destination-local accounting is optional.
		c.queuesMu.RLock()
		q := c.queues[r.DID]
		c.queuesMu.RUnlock()
		c.recordTerminalDrop(r.DID, q, &deliveryItem{pduType: PDUTypeX2, xid: r.XID, data: r.Data, queued: r.AdmittedAt}, "administrative_purge")
		return nil
	})
}

// ReservedJournalBytes accounts record indexes, bounded operation metadata,
// checkpoint IDs, recovery/export metadata and worst-case single-worker encoding
// and decoding buffers. Payload ingress shares the immutable queue allocation.
func (c ClientConfig) ReservedJournalBytes() int64 {
	// At most two exact-capacity sorted replay snapshots coexist during a
	// rebuild (2m *32 bytes each). The512MiB reserve also covers two Go
	// per-DID stream maps in the worst case of one distinct DID per record,
	// bounded approval IDs and manifest buffers. Payloads stay lazy and are
	// separately charged by the backend and destination queues.
	const segmentedOwner = SegmentedJournalMemoryBytes + (512 << 20)
	var total int64
	if c.X3SpoolDir != "" {
		total += segmentedOwner
		if c.X2SpoolDir != "" {
			total += segmentedOwner
		}
		return total
	}
	if c.X2SpoolDir != "" {
		records := min(c.X2SpoolMaxBytes/4096, 1_000_000)
		x2, _ := c.EffectiveQueueSizes()
		total = 4*journalMaxRecord + records*1536 + int64(x2)*512 + 8<<20
	}
	return total
}

func (c *Client) PurgeHeldX3() error {
	j := c.x3Journal
	if j == nil {
		return nil
	}
	j.controlMu.Lock()
	defer j.controlMu.Unlock()
	return j.VisitHeld(func(r JournalRecord) error {
		if err := j.Purge(r.ID); err != nil {
			return err
		}
		c.recordTerminalDrop(r.DID, nil, &deliveryItem{pduType: PDUTypeX3, xid: r.XID, data: r.Data, queued: r.AdmittedAt}, "administrative_purge")
		return nil
	})
}
