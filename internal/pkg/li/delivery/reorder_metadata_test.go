//go:build li

package delivery

import (
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/li"
	"github.com/stretchr/testify/require"
)

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
