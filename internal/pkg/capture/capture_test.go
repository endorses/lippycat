package capture

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewPacketBuffer(t *testing.T) {
	ctx := context.Background()
	bufferSize := 100

	buffer := NewPacketBuffer(ctx, bufferSize)

	assert.NotNil(t, buffer, "NewPacketBuffer should return non-nil buffer")
	assert.Equal(t, bufferSize, buffer.bufferSize, "Buffer size should match")
	assert.NotNil(t, buffer.ch, "Channel should be initialized")
	assert.NotNil(t, buffer.ctx, "Context should be initialized")
	assert.NotNil(t, buffer.cancel, "Cancel function should be initialized")
	assert.Equal(t, int64(0), atomic.LoadInt64(&buffer.dropped), "Dropped count should start at 0")
}

func TestPacketBuffer_Send_Success(t *testing.T) {
	ctx := context.Background()
	buffer := NewPacketBuffer(ctx, 10)
	defer buffer.Close()

	// Create a test packet
	pkt := createTestPacket()

	// Send should succeed when buffer has space
	result := buffer.Send(pkt)
	assert.True(t, result, "Send should succeed when buffer has space")
	assert.Equal(t, int64(0), atomic.LoadInt64(&buffer.dropped), "No packets should be dropped")
}

func TestPacketBuffer_Send_BackpressureHandling(t *testing.T) {
	ctx := context.Background()
	bufferSize := 2 // Small buffer to test backpressure
	buffer := NewPacketBuffer(ctx, bufferSize)
	defer buffer.Close()

	pkt := createTestPacket()

	// Fill the buffer
	for i := 0; i < bufferSize; i++ {
		result := buffer.Send(pkt)
		assert.True(t, result, "Send %d should succeed", i+1)
	}

	// Next send should fail due to backpressure and increment dropped count
	result := buffer.Send(pkt)
	assert.False(t, result, "Send should fail when buffer is full")
	assert.Equal(t, int64(1), atomic.LoadInt64(&buffer.dropped), "Should have 1 dropped packet")

	// Additional sends should continue to fail and increment drop count
	result = buffer.Send(pkt)
	assert.False(t, result, "Send should continue to fail")
	assert.Equal(t, int64(2), atomic.LoadInt64(&buffer.dropped), "Should have 2 dropped packets")
}

func TestPacketBuffer_Send_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	buffer := NewPacketBuffer(ctx, 10)
	defer buffer.Close()

	pkt := createTestPacket()

	// Send should work before cancellation
	result := buffer.Send(pkt)
	assert.True(t, result, "Send should succeed before context cancellation")

	// Cancel the context
	cancel()

	// Give a brief moment for cancellation to take effect
	time.Sleep(10 * time.Millisecond)

	// Send should fail after context cancellation
	result = buffer.Send(pkt)
	assert.False(t, result, "Send should fail after context cancellation")
}

func TestPacketBuffer_Receive(t *testing.T) {
	ctx := context.Background()
	buffer := NewPacketBuffer(ctx, 10)
	defer buffer.Close()

	pkt := createTestPacket()

	// Send a packet
	sent := buffer.Send(pkt)
	require.True(t, sent, "Must be able to send test packet")

	// Receive the packet
	ch := buffer.Receive()
	select {
	case receivedPkt := <-ch:
		assert.Equal(t, pkt.Packet.Data(), receivedPkt.Packet.Data(), "Received packet should match sent packet")
	case <-time.After(1 * time.Second):
		t.Fatal("Should have received packet within timeout")
	}
}

func TestPacketBuffer_Close(t *testing.T) {
	ctx := context.Background()
	buffer := NewPacketBuffer(ctx, 10)

	// Initially should not be closed
	assert.False(t, buffer.IsClosed(), "Buffer should not be closed initially")

	// Drop some packets to test logging
	pkt := createTestPacket()
	// Fill buffer and cause drops
	for i := 0; i < 15; i++ {
		buffer.Send(pkt)
	}

	// Close should not panic and should log dropped packets
	assert.NotPanics(t, func() {
		buffer.Close()
	}, "Close should not panic")

	// Should be closed after Close() is called
	assert.True(t, buffer.IsClosed(), "Buffer should be closed after Close()")

	// After close, sends should fail
	result := buffer.Send(pkt)
	assert.False(t, result, "Send should fail after close")
}

func TestPacketBuffer_ConcurrentAccess(t *testing.T) {
	ctx := context.Background()
	buffer := NewPacketBuffer(ctx, 100)
	defer buffer.Close()

	const numSenders = 10
	const packetsPerSender = 50

	// Start multiple senders
	done := make(chan bool, numSenders)
	for i := 0; i < numSenders; i++ {
		go func() {
			defer func() { done <- true }()
			pkt := createTestPacket()
			for j := 0; j < packetsPerSender; j++ {
				buffer.Send(pkt)
				// Small delay to allow interleaving
				time.Sleep(time.Microsecond)
			}
		}()
	}

	// Start receiver
	var receivedCount int64
	go func() {
		ch := buffer.Receive()
		for range ch {
			atomic.AddInt64(&receivedCount, 1)
		}
	}()

	// Wait for all senders to complete
	for i := 0; i < numSenders; i++ {
		<-done
	}

	// Give some time for packets to be processed
	time.Sleep(100 * time.Millisecond)

	// Verify counts
	totalSent := numSenders * packetsPerSender
	dropped := atomic.LoadInt64(&buffer.dropped)
	received := atomic.LoadInt64(&receivedCount)

	// Some packets may be dropped due to concurrent access, but total should make sense
	assert.LessOrEqual(t, dropped, int64(totalSent), "Dropped count should not exceed total sent")
	assert.GreaterOrEqual(t, received+dropped, int64(float64(totalSent)*0.8), "Should receive most packets")
}

func TestPacketBuffer_DropLogging(t *testing.T) {
	ctx := context.Background()
	buffer := NewPacketBuffer(ctx, 1) // Very small buffer
	defer buffer.Close()

	pkt := createTestPacket()

	// Fill all buffers first (main + merged channel)
	// The merger goroutine moves packets from ch to mergedCh, so we need to
	// fill both to cause drops. With capacity 1+1=2 (ch + mergedCh),
	// we need to wait for the merger to stabilize.
	for i := 0; i < 10; i++ {
		buffer.Send(pkt)
		time.Sleep(time.Millisecond) // Let merger process
	}

	// Now cause drops - the buffers should be full
	// Send many packets to ensure we get at least 1000 drops for logging
	sentCount := 0
	for i := 0; i < 2000; i++ {
		buffer.Send(pkt)
		sentCount++
	}

	// Check that drops occurred (exact number depends on timing with merger goroutine)
	dropped := buffer.GetDropped()
	sipDropped := buffer.GetSIPDropped()
	totalDropped := dropped + sipDropped

	assert.Greater(t, totalDropped, int64(1000), "Should have at least 1000 dropped packets to trigger logging")
}

func TestPacketBuffer_HighThroughput(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping high throughput test in short mode")
	}

	ctx := context.Background()
	buffer := NewPacketBuffer(ctx, 10000) // Large buffer
	defer buffer.Close()

	const numPackets = 100000
	pkt := createTestPacket()

	// Start a receiver to consume packets
	var received int64
	go func() {
		ch := buffer.Receive()
		for range ch {
			atomic.AddInt64(&received, 1)
		}
	}()

	start := time.Now()

	// Send packets as fast as possible
	sent := 0
	for i := 0; i < numPackets; i++ {
		if buffer.Send(pkt) {
			sent++
		}
	}

	duration := time.Since(start)

	// Give receiver time to catch up
	time.Sleep(100 * time.Millisecond)

	t.Logf("Sent %d packets in %v (%.0f packets/sec)", sent, duration, float64(sent)/duration.Seconds())

	// With a receiver, we should be able to send most packets
	assert.Greater(t, sent, numPackets/2, "Should be able to send at least half the packets")

	dropped := atomic.LoadInt64(&buffer.dropped)
	receivedCount := atomic.LoadInt64(&received)
	t.Logf("Sent: %d, Received: %d, Dropped: %d", sent, receivedCount, dropped)

	// Total should match
	assert.Equal(t, int64(numPackets), int64(sent)+dropped, "Total packets should equal sent + dropped")
}

func TestPacketBuffer_IsClosed(t *testing.T) {
	ctx := context.Background()
	buffer := NewPacketBuffer(ctx, 10)

	// Initially not closed
	assert.False(t, buffer.IsClosed(), "New buffer should not be closed")

	// After closing, should be closed
	buffer.Close()
	assert.True(t, buffer.IsClosed(), "Buffer should be closed after Close()")

	// Multiple calls to IsClosed should be safe
	assert.True(t, buffer.IsClosed(), "IsClosed should remain true after checking multiple times")
}

func TestGetPacketBufferSize_Default(t *testing.T) {
	// Test default buffer size
	size := getPacketBufferSize()
	assert.Equal(t, DefaultPacketBufferSize, size, "Should return default buffer size")
}

func TestPacketBuffer_PauseFn(t *testing.T) {
	ctx := context.Background()
	buffer := NewPacketBuffer(ctx, 10)
	defer buffer.Close()

	pkt := PacketInfo{}

	// Without pause function, Send should succeed
	assert.True(t, buffer.Send(pkt), "Send should succeed without pause function")

	// Set pause function that returns false (not paused)
	paused := false
	buffer.SetPauseFn(func() bool { return paused })

	assert.True(t, buffer.Send(pkt), "Send should succeed when not paused")

	// Set paused to true
	paused = true
	assert.False(t, buffer.Send(pkt), "Send should fail when paused")

	// Unpause
	paused = false
	assert.True(t, buffer.Send(pkt), "Send should succeed after unpause")
}

func TestPacketBuffer_PauseFn_NilSafe(t *testing.T) {
	ctx := context.Background()
	buffer := NewPacketBuffer(ctx, 10)
	defer buffer.Close()

	// Explicitly set nil pause function
	buffer.SetPauseFn(nil)

	pkt := PacketInfo{}
	assert.True(t, buffer.Send(pkt), "Send should succeed with nil pause function")
}
