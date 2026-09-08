//go:build li

package delivery

import (
	"context"
	"fmt"
	"github.com/endorses/lippycat/internal/pkg/li"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"sync"
	"testing"
	"time"
)

func TestQueueClaimCannotBeEvicted(t *testing.T) {
	q := newDestinationQueue(uuid.New(), 1)
	first := &deliveryItem{pduType: PDUTypeX3, data: []byte("a")}
	_, ok := q.enqueue(first)
	require.True(t, ok)
	require.Same(t, first, q.claim(PDUTypeX3))
	next := &deliveryItem{pduType: PDUTypeX3, data: []byte("b")}
	rejected, ok := q.enqueue(next)
	require.False(t, ok)
	require.Same(t, next, rejected)
	require.Same(t, first, q.peekBatch(1)[0])
	require.True(t, q.pop(first))
	require.Zero(t, q.snapshot().X3QueueBytes)
}
func TestQueueIndependentByteBudgets(t *testing.T) {
	q := newDestinationQueue(uuid.New(), 10)
	q.limits = [2]int64{4, 3}
	_, ok := q.enqueue(&deliveryItem{pduType: PDUTypeX2, data: []byte("1234")})
	require.True(t, ok)
	_, ok = q.enqueue(&deliveryItem{pduType: PDUTypeX3, data: []byte("123")})
	require.True(t, ok)
	oversized := &deliveryItem{pduType: PDUTypeX3, data: []byte("1234")}
	rejected, ok := q.enqueue(oversized)
	require.False(t, ok)
	require.Same(t, oversized, rejected)
	require.Equal(t, int64(4), q.snapshot().X2QueueBytes)
	require.Equal(t, int64(3), q.snapshot().X3QueueBytes)
}
func TestClientStopReconcilesVolatileGauges(t *testing.T) {
	c := NewClient(nil, DefaultClientConfig())
	q := c.getOrCreateQueue(uuid.New())
	item := &deliveryItem{pduType: PDUTypeX3, data: []byte("abc"), queued: time.Now()}
	_, ok := q.enqueue(item)
	require.True(t, ok)
	c.stats.QueueDepth = 1
	c.stats.QueueBytes = 3
	c.Stop()
	require.Zero(t, c.Stats().QueueDepth)
	require.Zero(t, c.Stats().QueueBytes)
	require.Equal(t, uint64(3), c.Stats().DroppedBytes)
}

func TestWriteDeadlineAfterControlLockIsKnownUnsent(t *testing.T) {
	conn, peer := tlsPipe(t)
	defer func() { require.NoError(t, peer.NetConn().Close()); require.NoError(t, conn.NetConn().Close()) }()
	did := uuid.New()
	m, state := testKeepaliveManager(did)
	m.registerConnection(state, conn, PDUTypeX3)
	runtimeValue, _ := m.connectionRuntime.Load(conn)
	runtime := runtimeValue.(*connectionRuntime)
	runtime.writeMu.Lock()
	err := m.WritePDUUntil(conn, []byte("expired"), time.Now().Add(5*time.Millisecond))
	runtime.writeMu.Unlock()
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.NotErrorIs(t, err, ErrUncertainWrite)
}

func TestReorderBudgetRetainsPayloadDuringCallback(t *testing.T) {
	const payload = 4096
	budget := NewReorderBudget(1 << 20)
	entered := make(chan struct{})
	release := make(chan struct{})
	done := make(chan struct{})
	rb := NewBudgetedCallAwareReorderBuffer(func(ReorderEntry) { close(entered); <-release }, time.Hour, budget, nil)
	go func() { rb.DeliverX3(1, 1, make([]byte, payload)); close(done) }()
	<-entered
	require.Equal(t, reorderBufferCharge+reorderStreamCharge+reorderPacketCharge+payload, budget.Used())
	rb.Discard()
	joined := make(chan struct{})
	go func() { rb.Wait(); close(joined) }()
	select {
	case <-joined:
		t.Fatal("joined an active callback")
	case <-time.After(5 * time.Millisecond):
	}
	require.Equal(t, int64(payload)+reorderPacketCharge, budget.Used())
	close(release)
	<-joined
	<-done
	require.Zero(t, budget.Used())
}

func TestPhysicalPayloadCountedOnceAcrossFanout(t *testing.T) {
	first, second := uuid.New(), uuid.New()
	m, _ := testKeepaliveManager(first)
	m.destinations[second] = &destinationState{dest: &li.Destination{DID: second}}
	c := NewClient(m, DefaultClientConfig())
	require.NoError(t, c.SendX2(uuid.New(), []uuid.UUID{first, second}, make([]byte, 1024)))
	require.Equal(t, int64(2048), c.Stats().QueueBytes)
	require.Equal(t, int64(1024), c.Stats().PhysicalQueueBytes)
	c.RemoveDestination(first)
	require.Equal(t, int64(1024), c.Stats().PhysicalQueueBytes)
	c.Stop()
	require.Zero(t, c.Stats().PhysicalQueueBytes)
}

func TestReorderOwnsDelayedPayloadAndRejectsStaleTimer(t *testing.T) {
	var delivered []string
	rb := NewCallAwareReorderBuffer(func(entry ReorderEntry) { delivered = append(delivered, string(entry.PDU)) }, time.Hour)
	var workers sync.WaitGroup
	rb.SetWorkerGroup(&workers)
	rb.DeliverCallX3("call", 1, 9, 1, []byte("base"))
	rb.DeliverCallX3("call", 1, 9, 3, []byte("discard"))
	key := reorderStreamKey{callID: "call", generation: 1, ssrc: 9}
	old := rb.streams[key]
	require.Equal(t, 1, rb.DiscardCall("call", 1))
	rb.DeliverCallX3("call", 1, 9, 10, []byte("newbase"))
	mutable := []byte("original")
	rb.DeliverCallX3("call", 1, 9, 12, mutable)
	copy(mutable, []byte("modified"))
	rb.flush(key, old, old.timerGeneration)
	packets, _ := rb.Buffered()
	require.Equal(t, 1, packets, "stale timer must not flush reused stream")
	rb.Stop()
	rb.Wait()
	workers.Wait()
	require.Equal(t, []string{"base", "newbase", "original"}, delivered)
}

func TestSynchronousMetadataUsesQueuedLifecycleIdentity(t *testing.T) {
	did := uuid.New()
	m, _ := testKeepaliveManager(did)
	c := NewClient(m, DefaultClientConfig())
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- c.SendX2SyncWithMetadata(ctx, uuid.New(), []uuid.UUID{did}, []byte("x2"), DeliveryMetadata{TaskGeneration: 9})
	}()
	require.Eventually(t, func() bool { return c.DestinationStats()[did].X2QueueDepth == 1 }, time.Second, time.Millisecond)
	item := c.getOrCreateQueue(did).peekBatch(1)[0]
	require.Equal(t, uint64(9), item.metadata.TaskGeneration)
	require.Zero(t, c.Stats().X2Queued, "sync admission does not change asynchronous call counters")
	cancel()
	require.ErrorIs(t, <-done, context.Canceled)
	c.Stop()
	require.Zero(t, c.Stats().PhysicalQueueBytes)
}

func TestExpiryHeapRemovesOnlyDueUnclaimedEntries(t *testing.T) {
	c := NewClient(nil, DefaultClientConfig())
	q := c.getOrCreateQueue(uuid.New())
	now := time.Now()
	later := &deliveryItem{pduType: PDUTypeX3, data: []byte("later"), metadata: DeliveryMetadata{Deadline: now.Add(time.Hour)}}
	earlier := &deliveryItem{pduType: PDUTypeX3, data: []byte("due"), metadata: DeliveryMetadata{Deadline: now.Add(-time.Second)}}
	for _, item := range []*deliveryItem{later, earlier} {
		_, ok := q.enqueue(item)
		require.True(t, ok)
		c.stats.QueueDepth++
		c.stats.QueueBytes += int64(len(item.data))
	}
	c.expireQueued(q)
	require.Equal(t, 1, q.depth())
	require.Same(t, later, q.peekBatch(1)[0])
	require.Len(t, q.expiry, 1)
	require.Equal(t, uint64(1), c.Stats().X3Dropped)
	c.Stop()
	require.Empty(t, q.expiry)
}

func TestShutdownKeepsClaimChargedUntilTransportResolves(t *testing.T) {
	for _, uncertain := range []bool{false, true} {
		t.Run(fmt.Sprint(uncertain), func(t *testing.T) {
			c := NewClient(nil, DefaultClientConfig())
			q := c.getOrCreateQueue(uuid.New())
			item := &deliveryItem{pduType: PDUTypeX3, data: []byte("active"), queued: time.Now(), metadata: DeliveryMetadata{Deadline: time.Now().Add(time.Hour)}}
			item.persisted.Store(true)
			c.attachPayload(item)
			_, ok := q.enqueue(item)
			require.True(t, ok)
			c.stats.QueueDepth = 1
			c.stats.QueueBytes = int64(len(item.data))
			require.Same(t, item, q.claim(PDUTypeX3))
			c.dropDestinationQueue(q, "shutdown_timeout")
			require.False(t, item.terminal.Load())
			require.Equal(t, int64(len(item.data)), c.Stats().QueueBytes)
			require.Equal(t, int64(len(item.data)), c.Stats().PhysicalQueueBytes)
			require.Equal(t, int64(len(item.data)), q.snapshot().X3InFlightBytes)
			item.uncertain.Store(uncertain)
			c.finishStoppedClaim(q, PDUTypeX3)
			c.finishStoppedClaim(q, PDUTypeX3)
			require.Zero(t, c.Stats().QueueDepth)
			require.Zero(t, c.Stats().QueueBytes)
			require.Zero(t, c.Stats().PhysicalQueueBytes)
			reason := "shutdown_timeout"
			if uncertain {
				reason = "uncertain_write"
			}
			require.Equal(t, uint64(1), q.snapshot().DroppedByReason[reason])
		})
	}
}

func TestStoppedTransportClaimRecordsUncertainty(t *testing.T) {
	for _, remove := range []bool{false, true} {
		t.Run(fmt.Sprint(remove), func(t *testing.T) {
			conn, peer := tlsPipe(t)
			did := uuid.New()
			manager, state := testKeepaliveManager(did)
			manager.registerConnection(state, conn, PDUTypeX3)
			manager.ReleaseConnection(did, conn)
			runtimeValue, _ := manager.connectionRuntime.Load(conn)
			runtime := runtimeValue.(*connectionRuntime)
			config := DefaultClientConfig()
			config.SendTimeout = time.Hour
			config.ShutdownTimeout = 10 * time.Millisecond
			client := NewClient(manager, config)
			client.Start()
			t.Cleanup(func() {
				require.NoError(t, peer.NetConn().Close())
				client.Stop()
				manager.Stop()
			})
			require.NoError(t, client.SendX3(uuid.New(), []uuid.UUID{did}, []byte("blocked product")))
			require.Eventually(t, func() bool {
				if runtime.writeMu.TryLock() {
					runtime.writeMu.Unlock()
					return false
				}
				return true
			}, time.Second, time.Millisecond)
			if remove {
				client.RemoveDestination(did)
			} else {
				client.Stop()
			}
			stats := client.Stats()
			require.Zero(t, stats.QueueDepth)
			require.Zero(t, stats.QueueBytes)
			require.Zero(t, stats.PhysicalQueueBytes)
			require.Equal(t, uint64(1), stats.UncertainWrites)
			require.Equal(t, uint64(1), stats.X3Dropped)
			require.Equal(t, uint64(1), stats.DroppedByReason["uncertain_write"])
			require.Zero(t, stats.DroppedByReason["shutdown_timeout"])
			require.Zero(t, stats.DroppedByReason["destination_removed"])
		})
	}
}
