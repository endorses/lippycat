//go:build li && linux

package delivery

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/li"
	"github.com/endorses/lippycat/internal/pkg/li/x2x3"
	"github.com/endorses/lippycat/internal/pkg/securestore"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func conflictDeliveryFixture(t *testing.T, persistent bool) (*Client, ClientConfig, *Manager, uuid.UUID, uuid.UUID, DeliveryMetadata) {
	t.Helper()
	cfg, manager, did, xid, meta, _ := x3ClientFixture(t)
	cfg.SendTimeout = time.Second
	if persistent {
		cfg.X2SpoolDir = filepath.Join(filepath.Dir(cfg.X3SpoolDir), "x2")
		cfg.X2SpoolKeyFile = filepath.Join(filepath.Dir(cfg.X3SpoolDir), "x2.key")
		require.NoError(t, os.WriteFile(cfg.X2SpoolKeyFile, bytes.Repeat([]byte{29}, 32), 0600))
		cfg.X2SpoolKeyID = "x2-conflict"
		cfg.X2SpoolMaxBytes = 384 << 20
	} else {
		cfg.X3SpoolDir = ""
		cfg.X3SpoolKeyFile = ""
		cfg.X3SpoolKeyID = ""
		cfg.X3SpoolMaxBytes = 0
	}
	c := NewClient(manager, cfg)
	require.NoError(t, c.Err())
	return c, cfg, manager, did, xid, meta
}

func enqueueConflictProducts(t *testing.T, c *Client, did, xid uuid.UUID, meta DeliveryMetadata) {
	t.Helper()
	pdu := x2x3.NewPDU(x2x3.PDUTypeX3, xid, 42)
	pdu.AddAttribute((&x2x3.TLVEncoder{}).EncodeUint32(x2x3.AttrSequenceNumber, 0))
	pdu.SetPayload([]byte("synthetic content"))
	x3, err := pdu.MarshalBinary()
	require.NoError(t, err)
	x2meta := meta
	x2meta.Provenance = li.DeliveryProvenance{}
	require.NoError(t, c.SendX2WithMetadata(xid, []uuid.UUID{did}, journalSequencePDU(t, xid, 0), x2meta))
	require.NoError(t, c.SendX3WithMetadata(xid, []uuid.UUID{did}, x3, meta))
	require.NoError(t, c.FlushPersistence(context.Background()))
	require.Eventually(t, func() bool { return c.QueueDepth() == 2 }, time.Second, time.Millisecond)
}

func TestConflictRevocationPreservesOrdinaryX2AndCancelsBothProducts(t *testing.T) {
	for _, persistent := range []bool{false, true} {
		name := "memory"
		if persistent {
			name = "journals"
		}
		t.Run(name, func(t *testing.T) {
			c, cfg, manager, did, xid, meta := conflictDeliveryFixture(t, persistent)
			enqueueConflictProducts(t, c, did, xid, meta)
			c.CancelTask(xid, meta.TaskGeneration)
			require.Eventually(t, func() bool { return c.QueueDepth() == 1 }, time.Second, time.Millisecond)
			require.Zero(t, c.Stats().X2Dropped)
			require.NoError(t, c.CancelTaskProducts(xid, meta.TaskGeneration))
			require.Zero(t, c.QueueDepth())
			require.Equal(t, uint64(1), c.Stats().X2Dropped)
			require.Error(t, c.SendX2WithMetadata(xid, []uuid.UUID{did}, journalSequencePDU(t, xid, 1), meta))
			if persistent {
				controls, err := c.DurableRevoker().Prepare(li.RevocationRequest{OperationID: uuid.New(), StateIncarnation: cfg.StateIncarnation, IncludeX2: true, Task: &li.InterceptTask{XID: xid, ActivationGeneration: meta.TaskGeneration}})
				require.NoError(t, err)
				require.Len(t, controls, 2)
				outcome, err := c.DurableRevoker().Commit(controls)
				require.NoError(t, err)
				require.Equal(t, securestore.Committed, outcome)
				c.Stop()
				c = NewClient(manager, cfg)
				require.NoError(t, c.Err())
				require.Zero(t, c.X3JournalStats().Retained)
				require.Zero(t, c.JournalStats().Retained)
				outcome, err = c.DurableRevoker().Commit(controls)
				require.NoError(t, err)
				require.Equal(t, securestore.Committed, outcome)
			}
			c.Stop()
		})
	}
}

func TestConflictRevocationDurableControlsCoverBothJournals(t *testing.T) {
	for _, failSecond := range []bool{false, true} {
		name := "success"
		if failSecond {
			name = "partial-failure"
		}
		t.Run(name, func(t *testing.T) {
			c, cfg, manager, did, xid, meta := conflictDeliveryFixture(t, true)
			enqueueConflictProducts(t, c, did, xid, meta)
			request := li.RevocationRequest{OperationID: uuid.New(), StateIncarnation: cfg.StateIncarnation, Task: &li.InterceptTask{XID: xid, ActivationGeneration: meta.TaskGeneration}}
			ordinary, err := c.DurableRevoker().Prepare(request)
			require.NoError(t, err)
			require.Len(t, ordinary, 1)
			require.Equal(t, c.x3Journal.UUID(), ordinary[0].JournalUUID)
			request.IncludeX2 = true
			controls, err := c.DurableRevoker().Prepare(request)
			require.NoError(t, err)
			require.Len(t, controls, 2)
			require.Equal(t, 1, c.JournalStats().Retained)
			require.Equal(t, 1, c.X3JournalStats().Retained)
			if failSecond {
				c.x3Journal.segments.(*journalSegments).commitFrame = func(*securestore.FixedSegment, []byte, []byte) (securestore.Outcome, error) {
					return securestore.NotCommitted, errors.New("injected second-journal failure")
				}
			}
			outcome, err := c.DurableRevoker().Commit(controls)
			if failSecond {
				require.Error(t, err)
				require.Equal(t, securestore.Uncertain, outcome)
			} else {
				require.NoError(t, err)
				require.Equal(t, securestore.Committed, outcome)
			}
			require.False(t, c.itemEligible(did, &deliveryItem{pduType: PDUTypeX2, xid: xid, metadata: meta}, false))
			require.False(t, c.itemEligible(did, &deliveryItem{pduType: PDUTypeX3, xid: xid, metadata: meta}, false))
			require.Zero(t, c.QueueDepth())
			c.Stop()
			c = NewClient(manager, cfg)
			require.NoError(t, c.Err())
			defer c.Stop()
			// Persisted administrative intent replays exactly these stable controls after
			// a partial boundary. It must finish both owners before enforcement resumes.
			outcome, err = c.DurableRevoker().Commit(controls)
			require.NoError(t, err)
			require.Equal(t, securestore.Committed, outcome)
			require.Zero(t, c.JournalStats().Retained)
			require.Zero(t, c.X3JournalStats().Retained)
		})
	}
}

func TestConflictRevocationJoinsBothTransportOwners(t *testing.T) {
	for _, persistent := range []bool{false, true} {
		for _, timeout := range []bool{false, true} {
			name := "memory"
			if persistent {
				name = "journal"
			}
			if timeout {
				name += "-timeout"
			}
			t.Run(name, func(t *testing.T) {
				c, cfg, manager, did, xid, meta := conflictDeliveryFixture(t, persistent)
				if timeout {
					c.config.SendTimeout = 40 * time.Millisecond
				}
				defer c.Stop()
				enqueueConflictProducts(t, c, did, xid, meta)
				var controls []*li.StateRevocation
				if persistent {
					var err error
					controls, err = c.DurableRevoker().Prepare(li.RevocationRequest{OperationID: uuid.New(), StateIncarnation: cfg.StateIncarnation, IncludeX2: true, Task: &li.InterceptTask{XID: xid, ActivationGeneration: meta.TaskGeneration}})
					require.NoError(t, err)
				}
				q := c.getOrCreateQueue(did)
				manager.mu.Lock()
				locked := true
				defer func() {
					if locked {
						manager.mu.Unlock()
					}
				}()
				c.Start()
				require.Eventually(t, func() bool {
					q.mu.Lock()
					defer q.mu.Unlock()
					return q.claims[0] != nil && q.claims[1] != nil && q.claims[0].item.cancel != nil && q.claims[1].item.cancel != nil
				}, time.Second, time.Millisecond)
				done := make(chan error, 1)
				go func() {
					if persistent {
						_, err := c.DurableRevoker().Commit(controls)
						done <- err
					} else {
						done <- c.CancelTaskProducts(xid, meta.TaskGeneration)
					}
				}()
				require.Eventually(t, func() bool {
					q.mu.Lock()
					defer q.mu.Unlock()
					return q.claims[0].item.canceled.Load() && q.claims[1].item.canceled.Load()
				}, time.Second, time.Millisecond)
				if timeout {
					select {
					case err := <-done:
						require.ErrorIs(t, err, context.DeadlineExceeded)
					case <-time.After(time.Second):
						t.Fatal("join did not honor send timeout")
					}
				} else {
					select {
					case err := <-done:
						t.Fatalf("returned before transport owners resolved: %v", err)
					default:
					}
				}
				manager.mu.Unlock()
				locked = false
				if !timeout {
					select {
					case err := <-done:
						require.NoError(t, err)
					case <-time.After(time.Second):
						t.Fatal("join did not complete")
					}
				}
				require.Eventually(t, func() bool {
					q.mu.Lock()
					defer q.mu.Unlock()
					return q.claims[0] == nil && q.claims[1] == nil && q.items[0].Len() == 0 && q.items[1].Len() == 0
				}, time.Second, time.Millisecond)
				require.Equal(t, uint64(1), c.Stats().X2Dropped)
				require.Equal(t, uint64(1), c.Stats().X3Dropped)
			})
		}
	}
}

func TestConflictRevocationGateCapacityStillWithdrawsQueuedWork(t *testing.T) {
	c, _, _, did, xid, meta := conflictDeliveryFixture(t, false)
	defer c.Stop()
	enqueueConflictProducts(t, c, did, xid, meta)
	for i := 0; i < maxDeliveryGateIdentities; i++ {
		c.conflictGenerations[uuid.New()] = 1
	}
	require.ErrorIs(t, c.CancelTaskProducts(xid, meta.TaskGeneration), ErrQueueFull)
	require.True(t, c.conflictGateFault)
	require.Zero(t, c.QueueDepth())
	require.Equal(t, uint64(1), c.Stats().X2Dropped)
	require.Equal(t, uint64(1), c.Stats().X3Dropped)
	require.Len(t, c.conflictGenerations, maxDeliveryGateIdentities)
}

// Pure coordinator probe; real encrypted journal restart/fault cases above
// remain required to establish the storage side of the revocation boundary.
type conflictControlBackend struct {
	journalSegmentBackend
	controls []*li.StateRevocation
	fail     bool
}

func (b *conflictControlBackend) highwaters() (uint64, uint64) { return 3, 4 }
func (b *conflictControlBackend) revoke(control *li.StateRevocation) (securestore.Outcome, error) {
	if b.fail {
		return securestore.NotCommitted, errors.New("injected control failure")
	}
	b.controls = append(b.controls, control)
	return securestore.Committed, nil
}

func TestConflictRevocationControlPlanBoundsAndPartialOutcome(t *testing.T) {
	state, xid := uuid.New(), uuid.New()
	x2, x3 := &conflictControlBackend{}, &conflictControlBackend{}
	c := &Client{config: ClientConfig{StateIncarnation: state, SendTimeout: time.Second}, queues: make(map[uuid.UUID]*destinationQueue), revoked: make(map[uuid.UUID]*li.StateRevocation), x2Journal: &Journal{storeID: [16]byte(uuid.New()), segments: x2}, x3Journal: &Journal{storeID: [16]byte(uuid.New()), segments: x3}}
	controls, err := c.DurableRevoker().Prepare(li.RevocationRequest{OperationID: uuid.New(), StateIncarnation: state, IncludeX2: true, Task: &li.InterceptTask{XID: xid, ActivationGeneration: 7}})
	require.NoError(t, err)
	require.Len(t, controls, 2)
	for i := 0; i < maxDeliveryGateIdentities-1; i++ {
		c.revoked[uuid.New()] = &li.StateRevocation{}
	}
	out, err := c.DurableRevoker().Commit(controls)
	require.ErrorIs(t, err, ErrQueueFull)
	require.Equal(t, securestore.NotCommitted, out)
	require.Empty(t, x2.controls)
	require.Empty(t, x3.controls)
	require.Len(t, c.revoked, maxDeliveryGateIdentities-1)
	clear(c.revoked)
	x3.fail = true
	out, err = c.DurableRevoker().Commit(controls)
	require.Error(t, err)
	require.Equal(t, securestore.Uncertain, out)
	require.Len(t, x2.controls, 1)
	require.Empty(t, x3.controls)
	require.Len(t, c.revoked, 2, "partial commit leaves both product gates closed")
	x3.fail = false
	out, err = c.DurableRevoker().Commit(controls)
	require.NoError(t, err)
	require.Equal(t, securestore.Committed, out)
	require.Len(t, x3.controls, 1)
}

func TestConflictRevocationX2JournalWithoutAdministrativeState(t *testing.T) {
	cfg, manager, did, xid, meta, _ := x3ClientFixture(t)
	cfg.X2SpoolDir, cfg.X2SpoolKeyFile, cfg.X2SpoolKeyID, cfg.X2SpoolMaxBytes = cfg.X3SpoolDir, cfg.X3SpoolKeyFile, cfg.X3SpoolKeyID, cfg.X3SpoolMaxBytes
	cfg.X3SpoolDir, cfg.X3SpoolKeyFile, cfg.X3SpoolKeyID, cfg.X3SpoolMaxBytes = "", "", "", 0
	cfg.StateIncarnation = uuid.Nil
	meta.StateIncarnation = uuid.Nil
	meta.Provenance = li.DeliveryProvenance{}
	c := NewClient(manager, cfg)
	require.NoError(t, c.Err())
	require.NoError(t, c.SendX2WithMetadata(xid, []uuid.UUID{did}, journalSequencePDU(t, xid, 0), meta))
	require.NoError(t, c.FlushPersistence(context.Background()))
	require.Equal(t, 1, c.JournalStats().Retained)
	require.NoError(t, c.CancelTaskProducts(xid, meta.TaskGeneration))
	require.Zero(t, c.JournalStats().Retained)
	c.Stop()
	c = NewClient(manager, cfg)
	require.NoError(t, c.Err())
	defer c.Stop()
	require.Zero(t, c.JournalStats().Retained)
}
