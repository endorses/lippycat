//go:build li

package delivery

import (
	"context"
	"sync"
	"testing"
	"time"
	"unsafe"

	"github.com/endorses/lippycat/internal/pkg/li"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func drainEntry(id string, generation uint64, incarnation uuid.UUID, value byte) ReorderEntry {
	return ReorderEntry{CallID: id, Generation: generation, Metadata: li.DeliveryMetadata{CallIncarnation: incarnation}, PDU: []byte{value}}
}

func TestReorderDrainExactIdentityAndNoReopening(t *testing.T) {
	old, reused := uuid.New(), uuid.New()
	var delivered []byte
	var rb *ReorderBuffer
	rb = NewCallAwareReorderBuffer(func(entry ReorderEntry) {
		// No callback may run while reorder's ownership mutex is held.
		rb.Buffered()
		delivered = append(delivered, entry.PDU[0])
	}, time.Hour)
	rb.DeliverEntryX3AfterCommit(drainEntry("call", 1, old, 1), 10, 1, nil)
	rb.DeliverEntryX3AfterCommit(drainEntry("call", 1, old, 3), 10, 3, nil)
	rb.DeliverEntryX3AfterCommit(drainEntry("call", 1, old, 5), 11, 1, nil)
	rb.DeliverEntryX3AfterCommit(drainEntry("call", 1, old, 7), 11, 3, nil)
	rb.DeliverEntryX3AfterCommit(drainEntry("call", 1, reused, 10), 10, 1, nil)
	rb.DeliverEntryX3AfterCommit(drainEntry("call", 1, reused, 12), 10, 3, nil)
	rb.DeliverEntryX3AfterCommit(drainEntry("other", 1, old, 20), 10, 1, nil)
	rb.DeliverEntryX3AfterCommit(drainEntry("other", 1, old, 22), 10, 3, nil)
	ticket, err := rb.DrainCall("call", 1, old)
	require.NoError(t, err)
	require.NoError(t, ticket.Wait(context.Background()))
	packets, _ := rb.Buffered()
	require.Equal(t, 2, packets, "other UUID and Call-ID remain buffered")
	require.ElementsMatch(t, []byte{1, 5, 10, 20, 3, 7}, delivered)
	var committed bool
	require.False(t, rb.AcceptEntryX3AfterCommit(drainEntry("call", 1, old, 8), 12, 1, func() { committed = true }))
	require.True(t, committed, "afterCommit remains a release hook even on rejection")
	require.True(t, rb.AcceptEntryX3AfterCommit(drainEntry("call", 2, uuid.New(), 30), 10, 1, nil))
	rb.Discard()
	rb.Wait()
}

func TestReorderDrainRejectedInsertionReleasesNewCallReservation(t *testing.T) {
	for _, extra := range []int64{0, reorderPacketCharge + 1} {
		budget := NewReorderBudget(reorderBufferCharge + reorderCallCharge + extra)
		rb := NewBudgetedCallAwareReorderBuffer(func(ReorderEntry) { t.Fatal("rejected packet delivered") }, time.Hour, budget, nil)
		entry := drainEntry("rejected", 1, uuid.New(), 1)
		// A settled opaque token needs no live client here: this test owns only
		// the reorder resource failure preceding packet acceptance.
		entry.Accepted = &AcceptedX3{}
		entry.Accepted.used.Store(true)
		require.False(t, rb.AcceptEntryX3AfterCommit(entry, 1, 1, nil))
		require.False(t, rb.HasAcceptedCall(entry.CallID, entry.Generation, entry.Metadata.CallIncarnation))
		require.Equal(t, reorderBufferCharge, budget.Used(), "neither packet-budget nor stream-budget rejection retains a closure identity")
		rb.Discard()
		rb.Wait()
		require.Zero(t, budget.Used())
	}
}

func TestReorderDrainFencesAlreadyDetachedTimerAndCoalesces(t *testing.T) {
	id := uuid.New()
	entered, release := make(chan struct{}), make(chan struct{})
	budget := NewReorderBudget(1 << 20)
	rb := NewBudgetedCallAwareReorderBuffer(func(entry ReorderEntry) {
		if entry.PDU[0] == 3 {
			close(entered)
			<-release
		}
	}, 5*time.Millisecond, budget, nil)
	rb.DeliverEntryX3AfterCommit(drainEntry("call", 8, id, 1), 1, 1, nil)
	rb.DeliverEntryX3AfterCommit(drainEntry("call", 8, id, 3), 1, 3, nil)
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("timer did not detach")
	}
	packets, _ := rb.Buffered()
	require.Zero(t, packets, "timer callback owns invisible detached entry")
	tickets := make([]*DrainTicket, 32)
	var wg sync.WaitGroup
	for n := range tickets {
		wg.Go(func() { var err error; tickets[n], err = rb.DrainCall("call", 8, id); require.NoError(t, err) })
	}
	wg.Wait()
	for _, ticket := range tickets {
		require.Same(t, tickets[0], ticket)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	require.ErrorIs(t, tickets[0].Wait(ctx), context.DeadlineExceeded)
	// Committing another call must not wait on a drain while holding rb.mu.
	committed, delivered := make(chan struct{}), make(chan struct{})
	go func() {
		rb.DeliverEntryX3AfterCommit(drainEntry("other", 9, uuid.New(), 1), 4, 1, func() { close(committed) })
		close(delivered)
	}()
	select {
	case <-committed:
	case <-time.After(time.Second):
		t.Fatal("drain blocked unrelated admission")
	}
	close(release)
	require.NoError(t, tickets[0].Wait(context.Background()))
	<-delivered
	rb.Stop()
	rb.Wait()
	require.Zero(t, budget.Used(), "one release per packet, stream, buffer and coalesced ticket")
}

func TestReorderDrainWinsTimerAndRetiresExactlyOnce(t *testing.T) {
	id := uuid.New()
	budget := NewReorderBudget(1 << 20)
	var mu sync.Mutex
	counts := map[byte]int{}
	rb := NewBudgetedCallAwareReorderBuffer(func(entry ReorderEntry) { mu.Lock(); counts[entry.PDU[0]]++; mu.Unlock() }, time.Hour, budget, nil)
	rb.DeliverEntryX3AfterCommit(drainEntry("call", 1, id, 1), 1, 1, nil)
	rb.DeliverEntryX3AfterCommit(drainEntry("call", 1, id, 3), 1, 3, nil)
	rb.mu.Lock()
	key := reorderStreamKey{callID: "call", generation: 1, incarnation: id, ssrc: 1}
	stream := rb.streams[key]
	timerGeneration := stream.timerGeneration
	rb.mu.Unlock()
	ticket, err := rb.DrainCall("call", 1, id)
	require.NoError(t, err)
	rb.flush(key, stream, timerGeneration) // timer that fired before disarm, then lost mu
	rb.Discard()
	require.NoError(t, ticket.Wait(context.Background()))
	rb.Wait()
	mu.Lock()
	require.Equal(t, map[byte]int{1: 1, 3: 1}, counts)
	mu.Unlock()
	require.Zero(t, budget.Used())
}

func TestReorderDrainValidationCapacityAndStructureCharges(t *testing.T) {
	budget := NewReorderBudget(reorderBufferCharge + reorderCallCharge - 1)
	rb := NewBudgetedCallAwareReorderBuffer(func(ReorderEntry) {}, time.Hour, budget, nil)
	for _, key := range []reorderCallKey{{}, {callID: "call", generation: 1}, {callID: "call", incarnation: uuid.New()}} {
		_, err := rb.DrainCall(key.callID, key.generation, key.incarnation)
		require.ErrorIs(t, err, ErrReorderDrain)
	}
	_, err := rb.DrainCall("call", 1, uuid.New())
	require.ErrorIs(t, err, ErrReorderDrain)
	require.Equal(t, reorderBufferCharge, budget.Used())
	rb.Discard()
	require.Zero(t, budget.Used())
	require.GreaterOrEqual(t, reorderPacketCharge, int64(6*unsafe.Sizeof(ReorderEntry{})+128), "expanded immutable metadata plus buffered/detached/sort scratch")
	require.GreaterOrEqual(t, reorderCallCharge, int64(unsafe.Sizeof(DrainTicket{})+unsafe.Sizeof(reorderCallKey{})+256+2048))
}
