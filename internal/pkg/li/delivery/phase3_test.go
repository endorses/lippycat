//go:build li

package delivery

import (
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"sync"
	"testing"
	"time"
)

func TestReorderPermanentGapDoesNotStarve(t *testing.T) {
	got := make(chan byte, 8)
	rb := NewReorderBuffer(func(p []byte) { got <- p[0] }, 20*time.Millisecond)
	defer rb.Stop()
	rb.DeliverX3(1, 10, []byte{10})
	<-got
	for i := byte(12); i < 16; i++ {
		rb.DeliverX3(1, uint16(i), []byte{i})
		time.Sleep(5 * time.Millisecond)
	}
	select {
	case v := <-got:
		assert.Equal(t, byte(12), v)
	case <-time.After(60 * time.Millisecond):
		t.Fatal("gap did not flush")
	}
	rb.DeliverX3(1, 16, []byte{16})
	select {
	case v := <-got:
		assert.Equal(t, byte(13), v)
	case <-time.After(time.Second):
		t.Fatal("subsequent packets stalled")
	}
}
func TestReorderLimitsAndCallbackOutsideLock(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	rb := NewReorderBufferWithLimits(func([]byte) {
		once.Do(func() { entered <- struct{}{}; <-release })
	}, time.Hour, 2, 1024)
	go rb.DeliverX3(1, 1, []byte{1})
	<-entered
	done := make(chan struct{})
	go func() { rb.Buffered(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("callback held reorder mutex")
	}
	close(release)
	rb.DeliverX3(1, 3, []byte{3})
	rb.DeliverX3(1, 4, []byte{4})
	rb.DeliverX3(1, 5, []byte{5})
	p, _ := rb.Buffered()
	require.LessOrEqual(t, p, 2)
	rb.Stop()
}

func TestReorderDiscardStopsWithoutDeliveringBufferedPDUs(t *testing.T) {
	var delivered [][]byte
	rb := NewReorderBuffer(func(pdu []byte) {
		delivered = append(delivered, append([]byte(nil), pdu...))
	}, time.Hour)

	rb.DeliverX3(7, 10, []byte("first"))
	rb.DeliverX3(7, 12, []byte("buffered"))
	require.Equal(t, [][]byte{[]byte("first")}, delivered)
	packets, bytes := rb.Buffered()
	require.Equal(t, 1, packets)
	require.Positive(t, bytes)

	rb.Discard()
	rb.DeliverX3(7, 11, []byte("after-stop"))

	assert.Equal(t, [][]byte{[]byte("first")}, delivered)
	packets, bytes = rb.Buffered()
	assert.Zero(t, packets)
	assert.Zero(t, bytes)
}

func TestReorderDiscardCallIsGenerationSelective(t *testing.T) {
	var mu sync.Mutex
	var delivered []ReorderEntry
	rb := NewCallAwareReorderBuffer(func(entry ReorderEntry) {
		mu.Lock()
		delivered = append(delivered, entry)
		mu.Unlock()
	}, 20*time.Millisecond)
	defer rb.Discard()

	rb.DeliverCallX3("call-a", 1, 7, 10, []byte("a-first"))
	rb.DeliverCallX3("call-a", 1, 7, 12, []byte("a-buffered"))
	rb.DeliverCallX3("call-b", 2, 7, 20, []byte("b-first"))
	rb.DeliverCallX3("call-b", 2, 7, 22, []byte("b-buffered"))

	require.Equal(t, 1, rb.DiscardCall("call-a", 1))
	require.Zero(t, rb.DiscardCall("call-a", 1))
	require.Eventually(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		for _, entry := range delivered {
			if string(entry.PDU) == "a-buffered" {
				return false
			}
		}
		return len(delivered) == 3
	}, time.Second, 5*time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, []ReorderEntry{
		{CallID: "call-a", Generation: 1, PDU: []byte("a-first")},
		{CallID: "call-b", Generation: 2, PDU: []byte("b-first")},
		{CallID: "call-b", Generation: 2, PDU: []byte("b-buffered")},
	}, delivered)
}

func TestReorderSeparatesReusedCallGenerationsWithSameSSRC(t *testing.T) {
	delivered := make(chan ReorderEntry, 4)
	rb := NewCallAwareReorderBuffer(func(entry ReorderEntry) { delivered <- entry }, time.Hour)
	defer rb.Discard()

	rb.DeliverCallX3("reused", 1, 99, 10, []byte("old"))
	rb.DeliverCallX3("reused", 2, 99, 40, []byte("new"))

	first := <-delivered
	second := <-delivered
	assert.Equal(t, uint64(1), first.Generation)
	assert.Equal(t, uint64(2), second.Generation)
}

func TestReorderRunsCommitHookBeforeSynchronousDelivery(t *testing.T) {
	committed := false
	rb := NewCallAwareReorderBuffer(func(ReorderEntry) {
		require.True(t, committed, "admission must be released before synchronous delivery re-admits")
	}, time.Second)
	t.Cleanup(rb.Discard)

	rb.DeliverCallX3AfterCommit("call-a", 1, 42, 10, []byte("first"), func() {
		committed = true
	})
}
func TestDestinationQueueSeparatesX2AndX3(t *testing.T) {
	q := newDestinationQueue(uuid.New(), 2)
	x2 := &deliveryItem{pduType: PDUTypeX2}
	require.Nil(t, mustEnqueue(t, q, x2))
	require.Nil(t, mustEnqueue(t, q, &deliveryItem{pduType: PDUTypeX3}))
	require.Nil(t, mustEnqueue(t, q, &deliveryItem{pduType: PDUTypeX3}))
	d := mustEnqueue(t, q, &deliveryItem{pduType: PDUTypeX3})
	assert.Equal(t, PDUTypeX3, d.pduType)
	batch := q.peekBatch(1)
	require.Equal(t, x2, batch[0])
	s := q.snapshot()
	assert.Equal(t, 1, s.X2QueueDepth)
	assert.Equal(t, 2, s.X3QueueDepth)
}
func mustEnqueue(t *testing.T, q *destinationQueue, item *deliveryItem) *deliveryItem {
	t.Helper()
	d, ok := q.enqueue(item)
	require.True(t, ok)
	return d
}
