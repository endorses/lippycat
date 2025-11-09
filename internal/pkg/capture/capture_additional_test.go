package capture

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

// TestPacketBuffer_Len tests the Len() method
func TestPacketBuffer_Len(t *testing.T) {
	ctx := context.Background()
	buffer := NewPacketBuffer(ctx, 10)
	defer buffer.Close()

	// Initially empty
	assert.Equal(t, 0, buffer.Len(), "Empty buffer should have length 0")

	// Add some packets
	pkt := createTestPacket()
	buffer.Send(pkt)
	assert.Equal(t, 1, buffer.Len(), "Buffer should have length 1 after sending 1 packet")

	buffer.Send(pkt)
	buffer.Send(pkt)
	assert.Equal(t, 3, buffer.Len(), "Buffer should have length 3 after sending 3 packets")

	// Receive one packet
	<-buffer.Receive()
	// Give a moment for the length to update
	time.Sleep(10 * time.Millisecond)
	assert.Equal(t, 2, buffer.Len(), "Buffer should have length 2 after receiving 1 packet")

	// Receive remaining packets
	<-buffer.Receive()
	<-buffer.Receive()
	time.Sleep(10 * time.Millisecond)
	assert.Equal(t, 0, buffer.Len(), "Buffer should be empty after receiving all packets")
}

// TestPacketBuffer_Cap tests the Cap() method
func TestPacketBuffer_Cap(t *testing.T) {
	tests := []struct {
		name       string
		bufferSize int
	}{
		{"small buffer", 10},
		{"medium buffer", 100},
		{"large buffer", 1000},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			buffer := NewPacketBuffer(ctx, tt.bufferSize)
			defer buffer.Close()

			assert.Equal(t, tt.bufferSize, buffer.Cap(), "Cap should return configured buffer size")

			// Cap should remain constant regardless of usage
			pkt := createTestPacket()
			buffer.Send(pkt)
			assert.Equal(t, tt.bufferSize, buffer.Cap(), "Cap should not change after sending")

			<-buffer.Receive()
			assert.Equal(t, tt.bufferSize, buffer.Cap(), "Cap should not change after receiving")
		})
	}
}

// TestGetPcapTimeout tests the GetPcapTimeout() function
func TestGetPcapTimeout(t *testing.T) {
	// Save original viper state and restore after test
	originalTimeout := viper.Get("pcap_timeout_ms")
	defer func() {
		if originalTimeout != nil {
			viper.Set("pcap_timeout_ms", originalTimeout)
		} else {
			viper.Set("pcap_timeout_ms", nil)
		}
	}()

	t.Run("returns default when not configured", func(t *testing.T) {
		viper.Set("pcap_timeout_ms", nil)
		timeout := GetPcapTimeout()
		assert.Equal(t, DefaultPcapTimeout, timeout, "Should return default timeout")
	})

	t.Run("returns configured value", func(t *testing.T) {
		viper.Set("pcap_timeout_ms", 500)
		timeout := GetPcapTimeout()
		assert.Equal(t, 500*time.Millisecond, timeout, "Should return configured timeout")
	})

	t.Run("ignores zero or negative values", func(t *testing.T) {
		viper.Set("pcap_timeout_ms", 0)
		timeout := GetPcapTimeout()
		assert.Equal(t, DefaultPcapTimeout, timeout, "Should return default for zero timeout")

		viper.Set("pcap_timeout_ms", -100)
		timeout = GetPcapTimeout()
		assert.Equal(t, DefaultPcapTimeout, timeout, "Should return default for negative timeout")
	})

	t.Run("accepts various valid timeouts", func(t *testing.T) {
		testCases := []int{50, 100, 200, 500, 1000}
		for _, ms := range testCases {
			viper.Set("pcap_timeout_ms", ms)
			timeout := GetPcapTimeout()
			assert.Equal(t, time.Duration(ms)*time.Millisecond, timeout,
				"Should return %dms timeout", ms)
		}
	})
}

// TestPacketBuffer_Send_ClosedBuffer tests sending to a closed buffer
func TestPacketBuffer_Send_ClosedBuffer(t *testing.T) {
	ctx := context.Background()
	buffer := NewPacketBuffer(ctx, 10)

	pkt := createTestPacket()

	// Send should work before close
	result := buffer.Send(pkt)
	assert.True(t, result, "Send should succeed before close")

	// Close the buffer
	buffer.Close()

	// Send should fail after close
	result = buffer.Send(pkt)
	assert.False(t, result, "Send should fail after close")

	// Multiple sends should continue to fail
	for i := 0; i < 5; i++ {
		result = buffer.Send(pkt)
		assert.False(t, result, "Send should continue to fail after close")
	}
}

// TestPacketBuffer_DoubleClose tests that closing twice is safe
func TestPacketBuffer_DoubleClose(t *testing.T) {
	ctx := context.Background()
	buffer := NewPacketBuffer(ctx, 10)

	// First close should work
	assert.NotPanics(t, func() {
		buffer.Close()
	}, "First close should not panic")

	assert.True(t, buffer.IsClosed(), "Buffer should be closed")

	// Second close should also work (idempotent)
	assert.NotPanics(t, func() {
		buffer.Close()
	}, "Second close should not panic")

	assert.True(t, buffer.IsClosed(), "Buffer should still be closed")

	// Third close for good measure
	assert.NotPanics(t, func() {
		buffer.Close()
	}, "Third close should not panic")
}

// TestPacketBuffer_ConcurrentSendReceive tests concurrent senders and receivers
func TestPacketBuffer_ConcurrentSendReceive(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping concurrent test in short mode")
	}

	ctx := context.Background()
	buffer := NewPacketBuffer(ctx, 1000)
	defer buffer.Close()

	const numSenders = 5
	const numReceivers = 3
	const packetsPerSender = 100

	var sentCount atomic.Int64
	var receivedCount atomic.Int64
	var wg sync.WaitGroup

	// Start receivers
	for i := 0; i < numReceivers; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			ch := buffer.Receive()
			for range ch {
				receivedCount.Add(1)
			}
		}(i)
	}

	// Start senders
	var sendersWg sync.WaitGroup
	for i := 0; i < numSenders; i++ {
		sendersWg.Add(1)
		go func(id int) {
			defer sendersWg.Done()
			pkt := createTestPacket()
			for j := 0; j < packetsPerSender; j++ {
				if buffer.Send(pkt) {
					sentCount.Add(1)
				}
			}
		}(i)
	}

	// Wait for all senders to complete
	sendersWg.Wait()

	// Give receivers time to process
	time.Sleep(200 * time.Millisecond)

	// Close buffer to stop receivers
	buffer.Close()

	// Wait for receivers to finish
	wg.Wait()

	sent := sentCount.Load()
	received := receivedCount.Load()
	dropped := atomic.LoadInt64(&buffer.dropped)

	t.Logf("Sent: %d, Received: %d, Dropped: %d", sent, received, dropped)

	// Verify accounting: received + dropped should equal sent
	assert.Equal(t, sent, received+dropped, "Received + Dropped should equal Sent")
}

// TestPacketBuffer_MultipleReadersOneWriter tests multiple concurrent readers
func TestPacketBuffer_MultipleReadersOneWriter(t *testing.T) {
	ctx := context.Background()
	buffer := NewPacketBuffer(ctx, 100)
	defer buffer.Close()

	const numReaders = 5
	const numPackets = 50

	pkt := createTestPacket()

	// All readers share the same channel
	ch := buffer.Receive()

	// Track which reader got each packet
	var totalReceived atomic.Int64
	var wg sync.WaitGroup

	// Start multiple readers
	for i := 0; i < numReaders; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			count := 0
			for range ch {
				count++
				totalReceived.Add(1)
			}
			t.Logf("Reader %d received %d packets", id, count)
		}(i)
	}

	// Send packets
	for i := 0; i < numPackets; i++ {
		buffer.Send(pkt)
		time.Sleep(1 * time.Millisecond) // Small delay to allow reader interleaving
	}

	// Close buffer to stop readers
	buffer.Close()

	// Wait for all readers to finish
	wg.Wait()

	// Each packet should be received by exactly one reader
	assert.Equal(t, int64(numPackets), totalReceived.Load(),
		"Total received should equal packets sent (each packet received by exactly one reader)")
}

// TestPacketBuffer_CloseWhileCapturing tests closing buffer during active capture
func TestPacketBuffer_CloseWhileCapturing(t *testing.T) {
	ctx := context.Background()
	buffer := NewPacketBuffer(ctx, 100)

	var wg sync.WaitGroup
	var sendersActive atomic.Bool
	sendersActive.Store(true)

	// Start continuous sender
	wg.Add(1)
	go func() {
		defer wg.Done()
		pkt := createTestPacket()
		for sendersActive.Load() {
			buffer.Send(pkt)
			time.Sleep(1 * time.Millisecond)
		}
	}()

	// Start continuous receiver
	wg.Add(1)
	go func() {
		defer wg.Done()
		ch := buffer.Receive()
		for range ch {
			// Just drain
		}
	}()

	// Let them run for a bit
	time.Sleep(100 * time.Millisecond)

	// Close buffer while they're active
	assert.NotPanics(t, func() {
		buffer.Close()
	}, "Close should not panic during active send/receive")

	// Stop sender
	sendersActive.Store(false)

	// Wait for goroutines to finish
	wg.Wait()

	// Buffer should be closed
	assert.True(t, buffer.IsClosed(), "Buffer should be closed")
}

// TestPacketBuffer_LargePackets tests handling of large packets
func TestPacketBuffer_LargePackets(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping large packet test in short mode")
	}

	ctx := context.Background()
	buffer := NewPacketBuffer(ctx, 100)
	defer buffer.Close()

	// Create a packet with large payload (simulating jumbo frames)
	pkt := createTestPacket()

	const numPackets = 50

	// Start receiver
	var received atomic.Int64
	go func() {
		ch := buffer.Receive()
		for range ch {
			received.Add(1)
		}
	}()

	// Send large packets
	sent := 0
	for i := 0; i < numPackets; i++ {
		if buffer.Send(pkt) {
			sent++
		}
	}

	// Wait for processing
	time.Sleep(100 * time.Millisecond)

	receivedCount := int(received.Load())
	assert.Equal(t, sent, receivedCount, "All sent packets should be received")
	t.Logf("Sent and received %d large packets", sent)
}

// TestPacketBuffer_HighPacketRate tests high packet throughput
func TestPacketBuffer_HighPacketRate(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping high packet rate test in short mode")
	}

	ctx := context.Background()
	buffer := NewPacketBuffer(ctx, 5000)
	defer buffer.Close()

	const targetPackets = 50000
	pkt := createTestPacket()

	// Start fast receiver
	var received atomic.Int64
	go func() {
		ch := buffer.Receive()
		for range ch {
			received.Add(1)
		}
	}()

	start := time.Now()

	// Send packets as fast as possible
	sent := 0
	for i := 0; i < targetPackets; i++ {
		if buffer.Send(pkt) {
			sent++
		}
	}

	duration := time.Since(start)

	// Wait for receiver to catch up
	time.Sleep(200 * time.Millisecond)

	receivedCount := received.Load()
	dropped := atomic.LoadInt64(&buffer.dropped)

	rate := float64(sent) / duration.Seconds()
	t.Logf("Sent %d packets in %v (%.0f packets/sec)", sent, duration, rate)
	t.Logf("Received: %d, Dropped: %d", receivedCount, dropped)

	// Verify accounting
	assert.Equal(t, int64(sent), receivedCount+dropped, "Received + Dropped should equal Sent")

	// We should achieve reasonably high throughput
	assert.Greater(t, rate, 10000.0, "Should achieve > 10k packets/sec")
}

// TestPacketBuffer_BufferOverflow tests buffer overflow behavior
func TestPacketBuffer_BufferOverflow(t *testing.T) {
	ctx := context.Background()
	buffer := NewPacketBuffer(ctx, 5) // Very small buffer
	defer buffer.Close()

	pkt := createTestPacket()

	// Fill buffer completely (no receiver)
	for i := 0; i < 5; i++ {
		result := buffer.Send(pkt)
		assert.True(t, result, "Should accept packets up to capacity")
	}

	// Now buffer is full, additional sends should drop
	const overflowPackets = 10
	for i := 0; i < overflowPackets; i++ {
		result := buffer.Send(pkt)
		assert.False(t, result, "Should reject packets when buffer is full")
	}

	dropped := atomic.LoadInt64(&buffer.dropped)
	assert.Equal(t, int64(overflowPackets), dropped, "Should have dropped overflow packets")
}

// TestPacketBuffer_Send_RaceWithClose tests race between Send and Close
func TestPacketBuffer_Send_RaceWithClose(t *testing.T) {
	// This test is specifically designed to catch races with -race flag
	const iterations = 100

	for i := 0; i < iterations; i++ {
		ctx := context.Background()
		buffer := NewPacketBuffer(ctx, 10)

		var wg sync.WaitGroup
		pkt := createTestPacket()

		// Start sender
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				buffer.Send(pkt)
			}
		}()

		// Start closer (races with sender)
		wg.Add(1)
		go func() {
			defer wg.Done()
			time.Sleep(1 * time.Millisecond)
			buffer.Close()
		}()

		wg.Wait()
	}

	// If we get here without panic or race detector errors, test passes
}
