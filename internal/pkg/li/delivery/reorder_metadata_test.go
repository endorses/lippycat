//go:build li

package delivery

import (
	"fmt"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/li"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestReorderEstablishesAdmissionBeforeBufferedDelay(t *testing.T) {
	for _, initial := range []struct {
		name string
		time time.Time
	}{
		{name: "missing"},
		{name: "future", time: time.Now().Add(time.Hour)},
	} {
		t.Run(initial.name, func(t *testing.T) {
			did := uuid.New()
			manager, _ := testKeepaliveManager(did)
			config := DefaultClientConfig()
			config.X3MaxAge = time.Millisecond
			client := NewClient(manager, config)
			defer client.Stop()
			var delivered ReorderEntry
			var deliveryErr error
			rb := NewCallAwareReorderBuffer(func(entry ReorderEntry) {
				if entry.PDU[0] == 3 {
					delivered = entry
					deliveryErr = client.SendX3WithMetadata(uuid.New(), []uuid.UUID{did}, entry.PDU, entry.Metadata)
				}
			}, time.Hour)
			defer func() { rb.Stop(); rb.Wait() }()
			rb.DeliverX3(1, 1, []byte{1})
			before := time.Now()
			rb.DeliverEntryX3AfterCommit(ReorderEntry{PDU: []byte{3}, Metadata: li.DeliveryMetadata{AdmittedAt: initial.time}}, 1, 3, nil)
			after := time.Now()
			// Final enqueue must include residence in the reorder gap, even
			// when the caller has no admission timestamp of its own.
			time.Sleep(5 * time.Millisecond)
			rb.Stop()
			rb.Wait()
			require.False(t, delivered.Metadata.AdmittedAt.Before(before))
			require.False(t, delivered.Metadata.AdmittedAt.After(after))
			require.ErrorIs(t, deliveryErr, ErrExpired)
			require.Zero(t, client.QueueDepth())
			require.Equal(t, uint64(1), client.Stats().DroppedByReason["expired"])
		})
	}
}

func TestReorderPreservesAdmissionMetadata(t *testing.T) {
	out := make(chan ReorderEntry, 3)
	rb := NewCallAwareReorderBuffer(func(e ReorderEntry) { out <- e }, 10*time.Millisecond)
	defer rb.Stop()
	admitted := time.Now().Add(-time.Second)
	meta := li.DeliveryMetadata{AdmittedAt: admitted, CapturedAt: admitted.Add(-time.Hour), Deadline: admitted.Add(5 * time.Minute), TaskGeneration: 7, DestinationGeneration: 8, CallGeneration: 9, CallID: "call"}
	entry := ReorderEntry{CallID: "call", Generation: 9, PDU: []byte{1}, Metadata: meta}
	rb.DeliverEntryX3AfterCommit(entry, 1, 1, nil)
	<-out
	entry.PDU = []byte{3}
	rb.DeliverEntryX3AfterCommit(entry, 1, 3, nil)
	select {
	case got := <-out:
		require.Equal(t, meta, got.Metadata)
		require.Equal(t, []byte{3}, got.PDU)
	case <-time.After(time.Second):
		t.Fatal("reorder did not flush idle gap")
	}
}

func TestReorderOwnsPayloadBeforeAfterCommit(t *testing.T) {
	for _, tc := range []struct {
		name string
		base []uint16
		seq  uint16
	}{
		{name: "initial", seq: 1},
		{name: "consecutive", base: []uint16{1}, seq: 2},
		{name: "late", base: []uint16{2}, seq: 1},
		{name: "gap", base: []uint16{1}, seq: 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var delivered []byte
			rb := NewCallAwareReorderBuffer(func(entry ReorderEntry) {
				delivered = append(delivered, entry.PDU...)
			}, time.Hour)
			for _, seq := range tc.base {
				rb.DeliverX3(1, seq, []byte{0})
			}
			delivered = nil
			payload := []byte{7}
			rb.DeliverEntryX3AfterCommit(ReorderEntry{PDU: payload}, 1, tc.seq, func() {
				// Admission has committed; releasing the producer's ownership
				// must not change bytes waiting for their delivery callback.
				payload[0] = 99
			})
			rb.Stop()
			rb.Wait()
			require.Equal(t, []byte{7}, delivered)
		})
	}
}

func TestReorderCallIdentityReachesDeliveryCancellation(t *testing.T) {
	for _, metadataGeneration := range []uint64{0, 99} {
		t.Run(fmt.Sprint(metadataGeneration), func(t *testing.T) {
			did := uuid.New()
			manager, _ := testKeepaliveManager(did)
			client := NewClient(manager, DefaultClientConfig())
			defer client.Stop()
			rb := NewCallAwareReorderBuffer(func(entry ReorderEntry) {
				require.NoError(t, client.SendX3WithMetadata(uuid.New(), []uuid.UUID{did}, entry.PDU, entry.Metadata))
			}, time.Hour)
			defer func() { rb.Stop(); rb.Wait() }()
			rb.DeliverEntryX3AfterCommit(ReorderEntry{
				CallID: "call", Generation: 7, PDU: []byte{1},
				Metadata: li.DeliveryMetadata{CallGeneration: metadataGeneration},
			}, 1, 1, nil)
			require.Equal(t, 1, client.QueueDepth())
			client.CancelCall("call", 7)
			require.Zero(t, client.QueueDepth(), "delivery must cancel the same call generation admitted by reorder")
			require.Equal(t, uint64(1), client.Stats().DroppedByReason["lifecycle_suppressed"])
		})
	}
}

func TestSharedReorderBudgetReleasedOnLifecycle(t *testing.T) {
	limit := reorderBufferCharge + reorderStreamCharge + reorderPacketCharge + 2048
	budget := NewReorderBudget(limit)
	discarded := 0
	rb := NewBudgetedCallAwareReorderBuffer(func(ReorderEntry) {}, time.Hour, budget, func(n int) { discarded += n })
	require.NotNil(t, rb)
	rb.DeliverCallX3("call", 1, 1, 1, []byte{1})
	rb.DeliverCallX3("call", 1, 1, 3, make([]byte, 2048))
	require.LessOrEqual(t, budget.Used(), limit)
	rb.DeliverCallX3("call", 1, 1, 5, make([]byte, 2048))
	require.Equal(t, 1, discarded)
	require.Equal(t, 1, rb.DiscardCall("call", 1))
	require.Equal(t, reorderBufferCharge, budget.Used())
	rb.Discard()
	require.Zero(t, budget.Used())
}

func TestSharedReorderBudgetReleasedOnFlush(t *testing.T) {
	budget := NewReorderBudget(reorderBufferCharge + reorderStreamCharge + 3*reorderPacketCharge + 1024)
	rb := NewBudgetedCallAwareReorderBuffer(func(ReorderEntry) {}, time.Hour, budget, nil)
	require.NotNil(t, rb)
	rb.DeliverCallX3("call", 1, 1, 1, []byte{1})
	rb.DeliverCallX3("call", 1, 1, 3, []byte{3})
	rb.DeliverCallX3("call", 1, 1, 2, []byte{2})
	require.Equal(t, reorderBufferCharge+reorderStreamCharge, budget.Used())
	rb.Stop()
	require.Zero(t, budget.Used())
}

func TestReorderResolvedGapDisarmsDeadline(t *testing.T) {
	rb := NewCallAwareReorderBuffer(func(ReorderEntry) {}, time.Hour)
	defer func() { rb.Stop(); rb.Wait() }()
	rb.DeliverCallX3("call", 1, 9, 1, []byte{1})
	rb.DeliverCallX3("call", 1, 9, 3, []byte{3})
	key := reorderStreamKey{callID: "call", generation: 1, ssrc: 9}
	s := rb.streams[key]
	require.NotNil(t, s.timer)
	rb.DeliverCallX3("call", 1, 9, 2, []byte{2})
	require.Nil(t, s.timer, "a resolved gap must not shorten the next gap's delay")
	require.True(t, s.deadline.IsZero())
}

func TestReorderRejectsPreviousTimerOnSameStream(t *testing.T) {
	var delivered []byte
	rb := NewCallAwareReorderBuffer(func(entry ReorderEntry) { delivered = append(delivered, entry.PDU[0]) }, time.Hour)
	defer func() { rb.Stop(); rb.Wait() }()
	rb.DeliverCallX3("call", 1, 9, 1, []byte{1})
	rb.DeliverCallX3("call", 1, 9, 3, []byte{3})
	key := reorderStreamKey{callID: "call", generation: 1, ssrc: 9}
	s := rb.streams[key]
	oldGeneration := s.timerGeneration
	rb.DeliverCallX3("call", 1, 9, 2, []byte{2})
	rb.DeliverCallX3("call", 1, 9, 5, []byte{5})
	newTimer := s.timer
	newTimerDone := s.timerDone
	defer func() {
		if newTimer.Stop() {
			newTimerDone()
		}
	}()
	// Model an old timer callback that fired before cancellation but only
	// acquires the buffer lock after a new gap has armed another timer.
	rb.flush(key, s, oldGeneration)
	packets, _ := rb.Buffered()
	require.Equal(t, 1, packets)
	require.Same(t, newTimer, s.timer)
	require.Equal(t, []byte{1, 2, 3}, delivered)
}

func TestReorderCallbacksPreserveCommittedOrder(t *testing.T) {
	out := make(chan byte, 3)
	rb := NewCallAwareReorderBuffer(func(entry ReorderEntry) { out <- entry.PDU[0] }, time.Hour)
	defer func() { rb.Stop(); rb.Wait() }()
	firstCommitted := make(chan struct{})
	releaseFirst := make(chan struct{})
	firstDone := make(chan struct{})
	go func() {
		defer close(firstDone)
		rb.DeliverCallX3AfterCommit("call", 1, 9, 1, []byte{1}, func() {
			close(firstCommitted)
			<-releaseFirst
		})
	}()
	<-firstCommitted
	secondCommitted := make(chan struct{})
	secondDone := make(chan struct{})
	go func() {
		defer close(secondDone)
		rb.DeliverCallX3AfterCommit("call", 1, 9, 2, []byte{2}, func() { close(secondCommitted) })
	}()
	<-secondCommitted
	// The second admission must be released before waiting on the first
	// callback; lifecycle callbacks may need that admission barrier.
	select {
	case value := <-out:
		close(releaseFirst)
		<-firstDone
		<-secondDone
		t.Fatalf("later committed callback overtook first packet: %d", value)
	case <-time.After(20 * time.Millisecond):
	}
	// Processor destinations own separate reorder buffers. A blocked callback
	// at one MDF must not delay another MDF's local delivery admission.
	otherOutput := make(chan byte, 1)
	other := NewCallAwareReorderBuffer(func(entry ReorderEntry) { otherOutput <- entry.PDU[0] }, time.Hour)
	other.DeliverCallX3("call", 1, 9, 7, []byte{7})
	require.Equal(t, byte(7), <-otherOutput)
	other.Stop()
	other.Wait()
	close(releaseFirst)
	<-firstDone
	<-secondDone
	require.Equal(t, byte(1), <-out)
	require.Equal(t, byte(2), <-out)
}
