//go:build processor || tap || all

package subscriber

import (
	"sync"
	"testing"
	"time"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestManager_AddAndRemove(t *testing.T) {
	m := NewManager(10)

	ch := m.Add("client-1")
	require.NotNil(t, ch)
	assert.Equal(t, 1, m.Count())

	m.Remove("client-1")
	assert.Equal(t, 0, m.Count())
}

func TestManager_Remove_ClosesChannel(t *testing.T) {
	m := NewManager(10)

	ch := m.Add("client-1")
	require.NotNil(t, ch)

	// Remove should close the channel
	m.Remove("client-1")

	// Channel should be closed - reading should return zero value and false
	select {
	case _, ok := <-ch:
		assert.False(t, ok, "channel should be closed")
	case <-time.After(100 * time.Millisecond):
		t.Fatal("channel read should not block on closed channel")
	}
}

func TestManager_Remove_NonExistent(t *testing.T) {
	m := NewManager(10)

	// Remove non-existent client should not panic
	m.Remove("non-existent")
	assert.Equal(t, 0, m.Count())
}

func TestManager_Broadcast_ToActiveSubscribers(t *testing.T) {
	m := NewManager(10)

	ch1 := m.Add("client-1")
	ch2 := m.Add("client-2")

	batch := &data.PacketBatch{
		Packets: []*data.CapturedPacket{{Data: []byte("test")}},
	}

	m.Broadcast(batch)

	// Both subscribers should receive the batch
	select {
	case received := <-ch1:
		assert.Len(t, received.Packets, 1)
	case <-time.After(100 * time.Millisecond):
		t.Fatal("client-1 should have received batch")
	}

	select {
	case received := <-ch2:
		assert.Len(t, received.Packets, 1)
	case <-time.After(100 * time.Millisecond):
		t.Fatal("client-2 should have received batch")
	}
}

func TestManager_Broadcast_HandlesClosedChannel(t *testing.T) {
	m := NewManager(10)

	ch := m.Add("client-1")
	require.NotNil(t, ch)

	// Remove (closes channel)
	m.Remove("client-1")

	batch := &data.PacketBatch{
		Packets: []*data.CapturedPacket{{Data: []byte("test")}},
	}

	// Should not panic (no subscribers remain after Remove)
	assert.NotPanics(t, func() {
		m.Broadcast(batch)
	})
}

func TestManager_Broadcast_ConcurrentRemove(t *testing.T) {
	m := NewManager(100)

	// Add many subscribers
	for i := 0; i < 50; i++ {
		m.Add(string(rune('a' + i)))
	}

	batch := &data.PacketBatch{
		Packets: []*data.CapturedPacket{{Data: []byte("test")}},
	}

	var wg sync.WaitGroup
	wg.Add(2)

	// Goroutine 1: Continuously broadcast
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			m.Broadcast(batch)
		}
	}()

	// Goroutine 2: Remove subscribers while broadcasting
	go func() {
		defer wg.Done()
		for i := 0; i < 50; i++ {
			m.Remove(string(rune('a' + i)))
		}
	}()

	// Should not panic or deadlock
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// Success
	case <-time.After(5 * time.Second):
		t.Fatal("concurrent broadcast and remove should not deadlock")
	}
}

func TestSafeChannel_TrySend_Success(t *testing.T) {
	sc := newSafeChannel(1)

	batch := &data.PacketBatch{Packets: []*data.CapturedPacket{{Data: []byte("test")}}}

	sent := sc.TrySend(batch)
	assert.True(t, sent)

	// Verify it was received
	received := <-sc.Chan()
	assert.Len(t, received.Packets, 1)
}

func TestSafeChannel_TrySend_FullChannel(t *testing.T) {
	sc := newSafeChannel(1)
	sc.TrySend(&data.PacketBatch{}) // Fill the buffer

	batch := &data.PacketBatch{}

	// Should not block and return false
	sent := sc.TrySend(batch)
	assert.False(t, sent)
}

func TestSafeChannel_TrySend_ClosedChannel(t *testing.T) {
	sc := newSafeChannel(1)
	sc.Close()

	batch := &data.PacketBatch{}

	// Should not panic and return false
	sent := sc.TrySend(batch)
	assert.False(t, sent)
}

func TestSafeChannel_Close_Idempotent(t *testing.T) {
	sc := newSafeChannel(1)

	// Close multiple times should not panic
	assert.NotPanics(t, func() {
		sc.Close()
		sc.Close()
		sc.Close()
	})
}

func TestSafeChannel_ConcurrentSendAndClose(t *testing.T) {
	sc := newSafeChannel(100)

	var wg sync.WaitGroup
	wg.Add(2)

	// Goroutine 1: Continuously send
	go func() {
		defer wg.Done()
		for i := 0; i < 1000; i++ {
			sc.TrySend(&data.PacketBatch{})
		}
	}()

	// Goroutine 2: Close at some point
	go func() {
		defer wg.Done()
		time.Sleep(1 * time.Millisecond)
		sc.Close()
	}()

	// Should not panic or deadlock
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// Success
	case <-time.After(5 * time.Second):
		t.Fatal("concurrent send and close should not deadlock")
	}
}

func TestManager_BackpressureStats(t *testing.T) {
	m := NewManager(10)

	// Add subscriber with small buffer
	ch := m.Add("client-1")
	require.NotNil(t, ch)

	batch := &data.PacketBatch{Packets: []*data.CapturedPacket{{Data: []byte("test")}}}

	// Broadcast once
	m.Broadcast(batch)

	broadcasts, drops := m.GetBackpressureStats()
	assert.Equal(t, uint64(1), broadcasts)
	assert.Equal(t, uint64(0), drops)

	// Drain channel
	<-ch
}

func TestManager_CheckLimit(t *testing.T) {
	m := NewManager(2)

	assert.False(t, m.CheckLimit())

	m.Add("client-1")
	assert.False(t, m.CheckLimit())

	m.Add("client-2")
	assert.True(t, m.CheckLimit())

	m.Remove("client-1")
	assert.False(t, m.CheckLimit())
}

func TestManager_CheckLimit_NoLimit(t *testing.T) {
	m := NewManager(0) // No limit

	for i := 0; i < 100; i++ {
		m.Add(string(rune(i)))
	}

	assert.False(t, m.CheckLimit())
}

func TestManager_SetFilter(t *testing.T) {
	m := NewManager(10)

	m.Add("client-1")
	m.SetFilter("client-1", []string{"hunter-1", "hunter-2"})

	// Verify filter is stored (internal, but we can check via DeleteFilter not panicking)
	m.DeleteFilter("client-1")
}

func TestManager_NextID(t *testing.T) {
	m := NewManager(10)

	id1 := m.NextID()
	id2 := m.NextID()
	id3 := m.NextID()

	assert.Equal(t, uint64(1), id1)
	assert.Equal(t, uint64(2), id2)
	assert.Equal(t, uint64(3), id3)
}
