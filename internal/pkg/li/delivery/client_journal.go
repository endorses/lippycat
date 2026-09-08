//go:build li

package delivery

import (
	"errors"
	"fmt"
	"github.com/google/uuid"

	"github.com/endorses/lippycat/internal/pkg/li"
	"github.com/endorses/lippycat/internal/pkg/li/x2x3"
)

func (c *Client) initJournal() {
	if c.config.X2SpoolDir == "" {
		return
	}
	x2, _ := c.config.EffectiveQueueSizes()
	c.journal, c.initErr = OpenJournal(JournalConfig{PreserveSequences: true, Dir: c.config.X2SpoolDir, KeyFile: c.config.X2SpoolKeyFile, MaxBytes: c.config.X2SpoolMaxBytes, MaxPending: x2, MaxRecords: int(min(c.config.X2SpoolMaxBytes/4096, 1_000_000))})
	if c.initErr == nil && c.config.X2SpoolReplayPolicy == "purge" {
		c.initErr = c.PurgeHeldX2()
		if c.initErr != nil {
			c.initErr = errors.Join(c.initErr, c.journal.Close())
		}
	}
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
	if c.journal == nil || item.pduType != PDUTypeX2 {
		return nil
	}
	if item.metadata.TaskGeneration == 0 || item.metadata.DestinationGeneration == 0 {
		return fmt.Errorf("persistent X2 requires nonzero task and destination generations")
	}
	// Held product precedes live X2 for this destination. Other destinations
	// retain their independent admission capacity.
	if c.journal.HoldsDestination(q.did) {
		return fmt.Errorf("X2 journal replay awaits authorization")
	}
	m := item.metadata
	id, err := c.journal.admit(JournalRecord{DID: q.did, XID: item.xid, TaskGeneration: m.TaskGeneration, DestinationGeneration: m.DestinationGeneration, CallGeneration: m.CallGeneration, CallID: m.CallID, AdmittedAt: m.AdmittedAt, CapturedAt: m.CapturedAt, Data: item.data}, func(id uint64, err error) {
		if err != nil {
			reason := "persistence_failed"
			if errors.Is(err, ErrPersistenceUncertain) {
				reason = "persistence_uncertain"
			}
			c.removeItem(q, item, reason)
			return
		}
		item.journalID.Store(id)
		item.persisted.Store(true)
		q.signal()
	}, false)
	// journalID is published only by the callback before persisted.Store; the
	// dispatcher reads it only after persisted.Load, avoiding an admission race.
	_ = id
	return err
}
func (c *Client) RestoreJournalSequences(s *x2x3.Sequencer) error {
	if c.initErr != nil {
		return c.initErr
	}
	if c.journal == nil {
		return nil
	}
	if err := c.journal.VisitSequences(s.RestoreCheckpoint); err != nil {
		return err
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
		q := c.getOrCreateQueue(r.DID)
		c.recordTerminalDrop(r.DID, q, &deliveryItem{pduType: PDUTypeX2, xid: r.XID, data: r.Data, queued: r.AdmittedAt}, "administrative_purge")
		return nil
	})
}

// ReservedJournalBytes accounts record indexes, bounded operation metadata,
// checkpoint IDs, recovery/export metadata and worst-case single-worker encoding
// and decoding buffers. Payload ingress shares the immutable queue allocation.
func (c ClientConfig) ReservedJournalBytes() int64 {
	if c.X2SpoolDir == "" {
		return 0
	}
	records := min(c.X2SpoolMaxBytes/4096, 1_000_000)
	x2, _ := c.EffectiveQueueSizes()
	return 4*journalMaxRecord + records*1536 + int64(x2)*512 + 8<<20
}
