//go:build li

package delivery

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/li"
	"github.com/endorses/lippycat/internal/pkg/li/x2x3"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestJournalReplayPublicationSerializedWithHold(t *testing.T) {
	did := uuid.New()
	j := &Journal{
		entries:   map[uint64]*journalEntry{1: {did: did, held: true, persisted: true, authorized: true}},
		heldByDID: map[uuid.UUID]int{did: 1},
		stats:     JournalStats{Held: 1, Persisted: 1, ReplayPending: 1},
	}
	q := newDestinationQueue(did, 1)
	q.preserveX2 = true
	item := &deliveryItem{pduType: PDUTypeX2, data: []byte("IRI")}
	item.journalID.Store(1)
	item.persisted.Store(true)

	// A removal owns the journal state while deciding whether this record is
	// already held. Replay must not publish a sendable queue pointer during it.
	j.mu.Lock()
	locked := true
	defer func() {
		if locked {
			j.mu.Unlock()
		}
	}()
	started, done := make(chan struct{}), make(chan bool, 1)
	go func() {
		close(started)
		_, ok := j.enqueueReplay(q, item)
		done <- ok
	}()
	<-started
	require.Never(t, func() bool {
		q.mu.Lock()
		defer q.mu.Unlock()
		return q.items[0].Len() != 0
	}, 30*time.Millisecond, time.Millisecond)
	j.mu.Unlock()
	locked = false
	select {
	case ok := <-done:
		require.True(t, ok)
	case <-time.After(time.Second):
		t.Fatal("replay publication blocked")
	}
	for _, removed := range q.stopAndDrain("destination_removed") {
		j.Hold(removed.journalID.Load())
	}
	require.Equal(t, 1, j.Stats().Held)
	require.Zero(t, j.Stats().ReplayPending)
	require.True(t, j.HoldsDestination(did))
}

func TestJournalManifestRequiresIdentityAndCurrentAuthorization(t *testing.T) {
	cfg := journalTestConfig(t)
	j, err := OpenJournal(cfg)
	require.NoError(t, err)
	did, xid := uuid.New(), uuid.New()
	dest := &li.Destination{DID: did, ProtocolType: "X2", CreatedAt: time.Now()}
	gen := li.DestinationDeliveryGeneration(dest)
	id := journalAdmit(t, j, JournalRecord{DID: did, XID: xid, TaskGeneration: 7, DestinationGeneration: gen, Data: journalSequencePDU(t, xid, 0), AdmittedAt: time.Now()})
	require.NoError(t, j.Close())
	config := DefaultClientConfig()
	config.X2SpoolDir = cfg.Dir
	config.X2SpoolKeyFile = cfg.KeyFile
	config.X2SpoolMaxBytes = cfg.MaxBytes
	manager := &Manager{destinations: map[uuid.UUID]*destinationState{did: {dest: dest}}}
	c := NewClient(manager, config)
	require.NoError(t, c.Err())
	defer c.Stop()
	export := filepath.Join(t.TempDir(), "manifest.json")
	require.NoError(t, c.ExportHeldJournalManifest(export))
	b, err := os.ReadFile(export)
	require.NoError(t, err)
	var m ReplayManifest
	require.NoError(t, json.Unmarshal(b, &m))
	require.Len(t, m.Records, 1)
	require.Equal(t, id, m.Records[0].ID)
	require.NoError(t, c.ReplayJournalManifest(export, func(JournalRecord) bool { return false }))
	require.Equal(t, 1, c.JournalStats().Held)
	require.Zero(t, c.QueueDepth())
	m.Records[0].TaskGeneration++
	bad, err := json.Marshal(m)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(export, bad, 0600))
	require.NoError(t, c.ReplayJournalManifest(export, func(JournalRecord) bool { return true }))
	require.Equal(t, 1, c.JournalStats().Held)
	require.NoError(t, os.WriteFile(export, b, 0600))
	require.NoError(t, c.ReplayJournalManifest(export, func(JournalRecord) bool { return true }))
	require.Eventually(t, func() bool { return c.JournalStats().Held == 0 && c.QueueDepth() == 1 }, time.Second, time.Millisecond)
	require.Equal(t, 1, c.QueueDepth())
	require.NoError(t, c.ReplayJournalManifest(export, func(JournalRecord) bool { return true }))
	require.Equal(t, 1, c.QueueDepth())
}
func TestJournalHeldBlocksLiveAndPurgeAccountsOnce(t *testing.T) {
	cfg := journalTestConfig(t)
	j, err := OpenJournal(cfg)
	require.NoError(t, err)
	did := uuid.New()
	xid := uuid.New()
	journalAdmit(t, j, JournalRecord{DID: did, XID: xid, Data: journalSequencePDU(t, xid, 0)})
	require.NoError(t, j.Close())
	config := DefaultClientConfig()
	config.X2SpoolDir = cfg.Dir
	config.X2SpoolKeyFile = cfg.KeyFile
	config.X2SpoolMaxBytes = cfg.MaxBytes
	c := NewClient(&Manager{destinations: make(map[uuid.UUID]*destinationState)}, config)
	require.NoError(t, c.Err())
	defer c.Stop()
	require.Error(t, c.SendX2(uuid.New(), []uuid.UUID{did}, []byte("new")))
	require.Equal(t, 1, c.JournalStats().Held)
	before := c.Stats().X2Dropped
	require.NoError(t, c.PurgeHeldX2())
	require.Equal(t, before+1, c.Stats().X2Dropped)
	require.Zero(t, c.JournalStats().Held)
	require.NoError(t, c.PurgeHeldX2())
	require.Equal(t, before+1, c.Stats().X2Dropped)
}

func TestJournalStartupPurgeDoesNotReserveHistoricalDestinations(t *testing.T) {
	cfg := journalTestConfig(t)
	j, err := OpenJournal(cfg)
	require.NoError(t, err)
	var bytes uint64
	for range 3 {
		xid := uuid.New()
		data := journalSequencePDU(t, xid, 0)
		bytes += uint64(len(data))
		journalAdmit(t, j, JournalRecord{DID: uuid.New(), XID: xid, Data: data})
	}
	require.NoError(t, j.Close())
	config := DefaultClientConfig()
	config.X2SpoolDir = cfg.Dir
	config.X2SpoolKeyFile = cfg.KeyFile
	config.X2SpoolMaxBytes = cfg.MaxBytes
	config.X2SpoolReplayPolicy = "purge"
	c := NewClient(&Manager{destinations: make(map[uuid.UUID]*destinationState)}, config)
	require.NoError(t, c.Err())
	defer c.Stop()
	require.Zero(t, c.JournalStats().Held)
	require.Equal(t, uint64(3), c.Stats().X2Dropped)
	require.Equal(t, bytes, c.Stats().DroppedBytes)
	c.queuesMu.RLock()
	queues := len(c.queues)
	c.queuesMu.RUnlock()
	require.Zero(t, queues, "historical destinations must not consume live queue reservations")
}

func TestJournalPendingPersistenceRetainedAfterQueueStops(t *testing.T) {
	for _, remove := range []bool{false, true} {
		t.Run(fmt.Sprintf("remove_destination_%t", remove), func(t *testing.T) {
			cfg := journalTestConfig(t)
			config := DefaultClientConfig()
			config.X2SpoolDir = cfg.Dir
			config.X2SpoolKeyFile = cfg.KeyFile
			config.X2SpoolMaxBytes = cfg.MaxBytes
			did, xid := uuid.New(), uuid.New()
			manager := &Manager{destinations: map[uuid.UUID]*destinationState{
				did: {dest: &li.Destination{DID: did, ProtocolType: "X2ANDX3", CreatedAt: time.Now()}},
			}}
			c := NewClient(manager, config)
			require.NoError(t, c.Err())
			defer c.Stop()
			entered, release := make(chan struct{}), make(chan struct{})
			write := c.journal.writeFile
			c.journal.writeFile = func(path string, data []byte) error {
				if filepath.Ext(path) == ".x2" {
					close(entered)
					<-release
				}
				return write(path, data)
			}
			require.NoError(t, c.SendX2WithMetadata(xid, []uuid.UUID{did}, journalSequencePDU(t, xid, 0), DeliveryMetadata{TaskGeneration: 1}))
			require.NoError(t, c.SendX3(xid, []uuid.UUID{did}, []byte("volatile")))
			<-entered
			q := c.getOrCreateQueue(did)
			removed := make(chan struct{})
			if remove {
				go func() {
					c.RemoveDestination(did)
					close(removed)
				}()
				require.Eventually(t, func() bool {
					q.mu.Lock()
					defer q.mu.Unlock()
					return q.stopped
				}, time.Second, time.Millisecond)
			} else {
				c.dropDestinationQueue(q, "destination_removed")
				close(removed)
			}
			// Pending storage must not be declared lost or release its reservation.
			depth, dropped := c.QueueDepth(), c.Stats().X2Dropped
			close(release)
			if remove {
				require.Equal(t, 2, depth)
			} else {
				require.Equal(t, 1, depth)
			}
			require.Zero(t, dropped)
			require.NoError(t, c.journal.Flush())
			<-removed
			require.Zero(t, c.QueueDepth())
			require.Zero(t, c.Stats().QueueBytes)
			require.Zero(t, c.Stats().X2Dropped)
			require.Equal(t, 1, c.JournalStats().Held)
			require.Equal(t, 1, c.JournalStats().Persisted)
			require.Equal(t, uint64(1), c.Stats().DroppedByReason["destination_removed"])
			require.Zero(t, c.Stats().DroppedByReason[""])
		})
	}
}

func TestJournalRestartRetainsX2BeyondX3Lifetime(t *testing.T) {
	cfg := journalTestConfig(t)
	config := DefaultClientConfig()
	config.X2SpoolDir = cfg.Dir
	config.X2SpoolKeyFile = cfg.KeyFile
	config.X2SpoolMaxBytes = cfg.MaxBytes
	config.X3MaxAge = 20 * time.Millisecond
	config.ShutdownTimeout = 10 * time.Millisecond
	manager := &Manager{destinations: make(map[uuid.UUID]*destinationState)}
	c := NewClient(manager, config)
	require.NoError(t, c.Err())
	did, xid := uuid.New(), uuid.New()
	manager.destinations[did] = &destinationState{dest: &li.Destination{DID: did, ProtocolType: "X2ANDX3", CreatedAt: time.Now()}}
	pdu := journalSequencePDU(t, xid, 3)
	require.NoError(t, c.SendX2WithMetadata(xid, []uuid.UUID{did}, pdu, DeliveryMetadata{TaskGeneration: 1}))
	require.NoError(t, c.SendX3(xid, []uuid.UUID{did}, []byte("volatile X3")))
	// Run only the outage age owner: no usable transport is available.
	q := c.getOrCreateQueue(did)
	c.wg.Add(1)
	q.workers.Add(1)
	go c.expiryDispatcher(q)
	require.Eventually(t, func() bool { return c.Stats().X3Dropped == 1 && c.JournalStats().Persisted == 1 }, time.Second, time.Millisecond)
	require.Zero(t, c.Stats().X2Dropped)
	c.Stop()
	require.Zero(t, c.Stats().X2Dropped)
	c = NewClient(manager, config)
	require.NoError(t, c.Err())
	defer c.Stop()
	require.Equal(t, 1, c.JournalStats().Held)
	var restored []byte
	require.NoError(t, c.journal.VisitHeld(func(r JournalRecord) error { restored = r.Data; return nil }))
	require.Equal(t, pdu, restored)
	require.Zero(t, c.Stats().X3Queued)
	s := x2x3.NewSequencer(10)
	require.NoError(t, c.RestoreJournalSequences(s))
	next, err := s.Next(x2x3.SequenceContext{PDUType: x2x3.PDUTypeX2, XID: xid, CorrelationID: 42})
	require.NoError(t, err)
	require.Equal(t, uint32(4), next)
}

func TestJournalReplayBacklogLargerThanMemoryQueue(t *testing.T) {
	cfg := journalTestConfig(t)
	j, err := OpenJournal(cfg)
	require.NoError(t, err)
	did, xid := uuid.New(), uuid.New()
	dest := &li.Destination{DID: did, ProtocolType: "X2", CreatedAt: time.Now()}
	gen := li.DestinationDeliveryGeneration(dest)
	var ids []uint64
	for n := 0; n < 3; n++ {
		ids = append(ids, journalAdmit(t, j, JournalRecord{DID: did, XID: xid, TaskGeneration: 7, DestinationGeneration: gen, Data: journalSequencePDU(t, xid, uint32(n)), AdmittedAt: time.Now()}))
	}
	require.NoError(t, j.Close())
	config := DefaultClientConfig()
	config.QueueSize = 1
	config.X2SpoolDir = cfg.Dir
	config.X2SpoolKeyFile = cfg.KeyFile
	config.X2SpoolMaxBytes = cfg.MaxBytes
	c := NewClient(&Manager{destinations: map[uuid.UUID]*destinationState{did: {dest: dest}}}, config)
	require.NoError(t, c.Err())
	defer c.Stop()
	require.NoError(t, c.ReplayHeldX2(func(JournalRecord) bool { return true }))
	for _, id := range ids {
		require.Eventually(t, func() bool { return c.QueueDepth() == 1 }, time.Second, time.Millisecond)
		q := c.getOrCreateQueue(did)
		item := q.claim(PDUTypeX2)
		require.NotNil(t, item)
		require.Equal(t, id, item.journalID.Load())
		require.True(t, q.pop(item))
		atomic.AddInt64(&c.stats.QueueDepth, -1)
		atomic.AddInt64(&c.stats.QueueBytes, -int64(len(item.data)))
		c.recordSuccess(q, item)
	}
	require.NoError(t, c.journal.Flush())
	require.Zero(t, c.JournalStats().Held)
	require.Zero(t, c.QueueDepth())
	require.Equal(t, uint64(3), c.Stats().X2Sent)
	require.Zero(t, c.Stats().X2Dropped)
}

func TestJournalReplayUnauthorizedHeadBlocksLaterAuthorizedProduct(t *testing.T) {
	cfg := journalTestConfig(t)
	j, err := OpenJournal(cfg)
	require.NoError(t, err)
	did, xid := uuid.New(), uuid.New()
	dest := &li.Destination{DID: did, ProtocolType: "X2", CreatedAt: time.Now()}
	gen := li.DestinationDeliveryGeneration(dest)
	first := journalAdmit(t, j, JournalRecord{DID: did, XID: xid, TaskGeneration: 7, DestinationGeneration: gen, Data: journalSequencePDU(t, xid, 1)})
	journalAdmit(t, j, JournalRecord{DID: did, XID: xid, TaskGeneration: 7, DestinationGeneration: gen, Data: journalSequencePDU(t, xid, 2)})
	require.NoError(t, j.Close())
	config := DefaultClientConfig()
	config.QueueSize = 1
	config.X2SpoolDir = cfg.Dir
	config.X2SpoolKeyFile = cfg.KeyFile
	config.X2SpoolMaxBytes = cfg.MaxBytes
	c := NewClient(&Manager{destinations: map[uuid.UUID]*destinationState{did: {dest: dest}}}, config)
	require.NoError(t, c.Err())
	defer c.Stop()
	q := c.getOrCreateQueue(did)
	q.mu.Lock()
	q.capacities[0] = 0
	q.mu.Unlock()
	require.NoError(t, c.ReplayHeldX2(func(JournalRecord) bool { return true }))
	// Revoke the earlier authorization while the queue has no capacity. A cached
	// replay index must preserve that held item as a barrier to later product.
	c.journal.controlMu.Lock()
	c.journal.mu.Lock()
	c.journal.entries[first].authorized = false
	c.journal.stats.ReplayPending--
	c.journal.mu.Unlock()
	q.mu.Lock()
	q.capacities[0] = 1
	q.mu.Unlock()
	c.journal.controlMu.Unlock()
	require.Never(t, func() bool { return c.QueueDepth() != 0 }, 50*time.Millisecond, time.Millisecond)
	require.NoError(t, c.ReplayHeldX2(func(JournalRecord) bool { return true }))
	require.Eventually(t, func() bool { return c.QueueDepth() == 1 }, time.Second, time.Millisecond)
	item := q.claim(PDUTypeX2)
	require.NotNil(t, item)
	require.Equal(t, first, item.journalID.Load())
}

func TestJournalHeldDestinationDoesNotBlockOtherDestinations(t *testing.T) {
	cfg := journalTestConfig(t)
	j, err := OpenJournal(cfg)
	require.NoError(t, err)
	a, b, xid := uuid.New(), uuid.New(), uuid.New()
	destA := &li.Destination{DID: a, ProtocolType: "X2", CreatedAt: time.Now()}
	destB := &li.Destination{DID: b, ProtocolType: "X2", CreatedAt: time.Now()}
	journalAdmit(t, j, JournalRecord{DID: a, XID: xid, TaskGeneration: 1, DestinationGeneration: li.DestinationDeliveryGeneration(destA), Data: journalSequencePDU(t, xid, 1)})
	require.NoError(t, j.Close())
	config := DefaultClientConfig()
	config.X2SpoolDir = cfg.Dir
	config.X2SpoolKeyFile = cfg.KeyFile
	config.X2SpoolMaxBytes = cfg.MaxBytes
	c := NewClient(&Manager{destinations: map[uuid.UUID]*destinationState{a: {dest: destA}, b: {dest: destB}}}, config)
	require.NoError(t, c.Err())
	defer c.Stop()
	pdu := journalSequencePDU(t, xid, 2)
	require.ErrorContains(t, c.SendX2WithMetadata(xid, []uuid.UUID{a}, pdu, DeliveryMetadata{TaskGeneration: 1}), "awaits authorization")
	require.NoError(t, c.SendX2WithMetadata(xid, []uuid.UUID{b}, pdu, DeliveryMetadata{TaskGeneration: 1}))
	require.NoError(t, c.journal.Flush())
	require.Equal(t, 2, c.JournalStats().Persisted)
	require.Equal(t, 1, c.JournalStats().Held)
	require.True(t, c.journal.HoldsDestination(a))
	require.False(t, c.journal.HoldsDestination(b))
}
