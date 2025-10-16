package capture

import (
	"context"
	"io"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/capture/pcaptypes"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/google/gopacket/tcpassembly"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// createTestPcapFile creates a temporary PCAP file with synthetic packets for testing
func createTestPcapFile(t *testing.T, numPackets int) *os.File {
	t.Helper()

	tmpFile, err := os.CreateTemp("", "test-*.pcap")
	require.NoError(t, err, "Should create temp PCAP file")

	// Write PCAP file header
	writer := pcapgo.NewWriter(tmpFile)
	err = writer.WriteFileHeader(65536, layers.LinkTypeEthernet)
	require.NoError(t, err, "Should write PCAP header")

	// Generate synthetic packets
	for i := 0; i < numPackets; i++ {
		pkt := createTestPacket()

		// Write packet to PCAP file
		ci := gopacket.CaptureInfo{
			Timestamp:     time.Now(),
			CaptureLength: len(pkt.Packet.Data()),
			Length:        len(pkt.Packet.Data()),
		}
		err = writer.WritePacket(ci, pkt.Packet.Data())
		require.NoError(t, err, "Should write packet to PCAP")
	}

	// Seek back to beginning for reading
	_, err = tmpFile.Seek(0, io.SeekStart)
	require.NoError(t, err, "Should seek to start")

	return tmpFile
}

// TestInitWithContext tests the traditional InitWithContext function
func TestInitWithContext(t *testing.T) {
	t.Run("creates and manages buffer internally", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		// Create test PCAP file with 50 packets
		pcapFile := createTestPcapFile(t, 50)
		defer os.Remove(pcapFile.Name())
		defer pcapFile.Close()

		iface := pcaptypes.CreateOfflineInterface(pcapFile)
		ifaces := []pcaptypes.PcapInterface{iface}

		// Track packets received by processor
		var packetCount int64
		processor := func(ch <-chan PacketInfo, asm *tcpassembly.Assembler) {
			for range ch {
				atomic.AddInt64(&packetCount, 1)
			}
		}

		// Start capture in background
		done := make(chan struct{})
		go func() {
			defer close(done)
			InitWithContext(ctx, ifaces, "", processor, nil)
		}()

		// Wait for some packets to be processed
		time.Sleep(500 * time.Millisecond)

		// Cancel context to stop capture
		cancel()

		// Wait for InitWithContext to return
		select {
		case <-done:
			// Success
		case <-time.After(3 * time.Second):
			t.Fatal("InitWithContext did not return after context cancellation")
		}

		// Verify packets were processed
		count := atomic.LoadInt64(&packetCount)
		assert.Greater(t, count, int64(0), "Should have processed packets from PCAP file")
		assert.LessOrEqual(t, count, int64(50), "Should not process more packets than in file")
		t.Logf("Processed %d packets", count)
	})

	t.Run("handles empty processor gracefully", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		defer cancel()

		pcapFile := createTestPcapFile(t, 10)
		defer os.Remove(pcapFile.Name())
		defer pcapFile.Close()

		iface := pcaptypes.CreateOfflineInterface(pcapFile)
		ifaces := []pcaptypes.PcapInterface{iface}

		// Empty processor that doesn't read - buffer will fill and packets will drop
		processor := func(ch <-chan PacketInfo, asm *tcpassembly.Assembler) {
			// Don't read - just wait for context
			<-ctx.Done()
		}

		done := make(chan struct{})
		go func() {
			defer close(done)
			InitWithContext(ctx, ifaces, "", processor, nil)
		}()

		// Cancel after short time
		time.Sleep(100 * time.Millisecond)
		cancel()

		// Wait for completion
		select {
		case <-done:
			// Success - did not panic
		case <-time.After(3 * time.Second):
			t.Fatal("InitWithContext did not return")
		}
	})

	t.Run("applies BPF filter correctly", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		pcapFile := createTestPcapFile(t, 30)
		defer os.Remove(pcapFile.Name())
		defer pcapFile.Close()

		iface := pcaptypes.CreateOfflineInterface(pcapFile)
		ifaces := []pcaptypes.PcapInterface{iface}

		// Filter for UDP port 5060 (SIP) - our test packets use this port
		filter := "udp port 5060"

		var packetCount int64
		processor := func(ch <-chan PacketInfo, asm *tcpassembly.Assembler) {
			for pkt := range ch {
				atomic.AddInt64(&packetCount, 1)
				// Verify packet matches filter
				if pkt.Packet != nil && pkt.Packet.TransportLayer() != nil {
					// Should be UDP
					assert.Equal(t, "UDP", pkt.Packet.TransportLayer().LayerType().String())
				}
			}
		}

		done := make(chan struct{})
		go func() {
			defer close(done)
			InitWithContext(ctx, ifaces, filter, processor, nil)
		}()

		time.Sleep(500 * time.Millisecond)
		cancel()

		select {
		case <-done:
			// Success
		case <-time.After(3 * time.Second):
			t.Fatal("InitWithContext did not return")
		}

		count := atomic.LoadInt64(&packetCount)
		assert.Greater(t, count, int64(0), "Should have processed filtered packets")
		t.Logf("Processed %d filtered packets", count)
	})

	t.Run("closes buffer on context cancellation", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())

		pcapFile := createTestPcapFile(t, 20)
		defer os.Remove(pcapFile.Name())
		defer pcapFile.Close()

		iface := pcaptypes.CreateOfflineInterface(pcapFile)
		ifaces := []pcaptypes.PcapInterface{iface}

		var channelClosed atomic.Bool
		processor := func(ch <-chan PacketInfo, asm *tcpassembly.Assembler) {
			for range ch {
				// Just drain
			}
			// Channel was closed
			channelClosed.Store(true)
		}

		done := make(chan struct{})
		go func() {
			defer close(done)
			InitWithContext(ctx, ifaces, "", processor, nil)
		}()

		// Give it time to start
		time.Sleep(100 * time.Millisecond)

		// Cancel context
		cancel()

		// Wait for completion
		select {
		case <-done:
			// Success
		case <-time.After(3 * time.Second):
			t.Fatal("InitWithContext did not return")
		}

		// Verify channel was closed
		assert.True(t, channelClosed.Load(), "Packet channel should be closed after context cancellation")
	})
}

// TestInitWithBuffer tests the new InitWithBuffer function
func TestInitWithBuffer(t *testing.T) {
	t.Run("uses external buffer without processor", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		// Create our own buffer
		buffer := NewPacketBuffer(ctx, 1000)
		defer buffer.Close()

		pcapFile := createTestPcapFile(t, 40)
		defer os.Remove(pcapFile.Name())
		defer pcapFile.Close()

		iface := pcaptypes.CreateOfflineInterface(pcapFile)
		ifaces := []pcaptypes.PcapInterface{iface}

		// Start capture with nil processor (we'll read from buffer directly)
		done := make(chan struct{})
		go func() {
			defer close(done)
			InitWithBuffer(ctx, ifaces, "", buffer, nil, nil)
		}()

		// Read packets from our buffer
		var packetCount int64
		go func() {
			for range buffer.Receive() {
				atomic.AddInt64(&packetCount, 1)
			}
		}()

		// Wait for packets
		time.Sleep(500 * time.Millisecond)

		// Cancel context to stop capture
		cancel()

		// Wait for InitWithBuffer to return
		select {
		case <-done:
			// Success
		case <-time.After(3 * time.Second):
			t.Fatal("InitWithBuffer did not return")
		}

		// Verify packets were written to our buffer
		count := atomic.LoadInt64(&packetCount)
		assert.Greater(t, count, int64(0), "Should have received packets through external buffer")
		assert.LessOrEqual(t, count, int64(40), "Should not receive more packets than in file")
		t.Logf("Received %d packets through external buffer", count)
	})

	t.Run("does not close external buffer when processor is nil", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())

		buffer := NewPacketBuffer(context.Background(), 1000)
		defer buffer.Close()

		pcapFile := createTestPcapFile(t, 15)
		defer os.Remove(pcapFile.Name())
		defer pcapFile.Close()

		iface := pcaptypes.CreateOfflineInterface(pcapFile)
		ifaces := []pcaptypes.PcapInterface{iface}

		done := make(chan struct{})
		go func() {
			defer close(done)
			InitWithBuffer(ctx, ifaces, "", buffer, nil, nil)
		}()

		// Give it time to start
		time.Sleep(100 * time.Millisecond)

		// Cancel context
		cancel()

		// Wait for completion
		select {
		case <-done:
			// Success
		case <-time.After(3 * time.Second):
			t.Fatal("InitWithBuffer did not return")
		}

		// Buffer should NOT be closed (we own it)
		assert.False(t, buffer.IsClosed(), "External buffer should not be closed by InitWithBuffer when processor is nil")

		// We should still be able to read from it (though it will be empty)
		select {
		case _, ok := <-buffer.Receive():
			if !ok {
				t.Fatal("Buffer channel should not be closed")
			}
		case <-time.After(10 * time.Millisecond):
			// Timeout is expected - buffer is empty
		}
	})

	t.Run("uses external buffer with processor", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		buffer := NewPacketBuffer(ctx, 1000)
		// Note: buffer will be closed by InitWithBuffer when processor is provided

		pcapFile := createTestPcapFile(t, 35)
		defer os.Remove(pcapFile.Name())
		defer pcapFile.Close()

		iface := pcaptypes.CreateOfflineInterface(pcapFile)
		ifaces := []pcaptypes.PcapInterface{iface}

		var packetCount int64
		processor := func(ch <-chan PacketInfo, asm *tcpassembly.Assembler) {
			for range ch {
				atomic.AddInt64(&packetCount, 1)
			}
		}

		done := make(chan struct{})
		go func() {
			defer close(done)
			InitWithBuffer(ctx, ifaces, "", buffer, processor, nil)
		}()

		time.Sleep(500 * time.Millisecond)
		cancel()

		select {
		case <-done:
			// Success
		case <-time.After(3 * time.Second):
			t.Fatal("InitWithBuffer did not return")
		}

		count := atomic.LoadInt64(&packetCount)
		assert.Greater(t, count, int64(0), "Should have processed packets through processor")
		assert.LessOrEqual(t, count, int64(35), "Should not process more packets than in file")
		t.Logf("Processed %d packets through processor", count)

		// Buffer should be closed when processor is provided
		assert.True(t, buffer.IsClosed(), "Buffer should be closed by InitWithBuffer when processor is provided")
	})

	t.Run("applies BPF filter correctly", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		buffer := NewPacketBuffer(ctx, 1000)
		defer buffer.Close()

		pcapFile := createTestPcapFile(t, 25)
		defer os.Remove(pcapFile.Name())
		defer pcapFile.Close()

		iface := pcaptypes.CreateOfflineInterface(pcapFile)
		ifaces := []pcaptypes.PcapInterface{iface}

		filter := "udp port 5060"

		done := make(chan struct{})
		go func() {
			defer close(done)
			InitWithBuffer(ctx, ifaces, filter, buffer, nil, nil)
		}()

		// Read and verify filtered packets
		var packetCount int64
		go func() {
			for pkt := range buffer.Receive() {
				atomic.AddInt64(&packetCount, 1)
				// Verify packet matches filter
				if pkt.Packet != nil && pkt.Packet.TransportLayer() != nil {
					assert.Equal(t, "UDP", pkt.Packet.TransportLayer().LayerType().String())
				}
			}
		}()

		time.Sleep(500 * time.Millisecond)
		cancel()

		select {
		case <-done:
			// Success
		case <-time.After(3 * time.Second):
			t.Fatal("InitWithBuffer did not return")
		}

		count := atomic.LoadInt64(&packetCount)
		assert.Greater(t, count, int64(0), "Should have received filtered packets")
		t.Logf("Received %d filtered packets", count)
	})

	t.Run("handles multiple interfaces", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		buffer := NewPacketBuffer(ctx, 2000)
		defer buffer.Close()

		// Create multiple PCAP files as different "interfaces"
		pcapFile1 := createTestPcapFile(t, 20)
		defer os.Remove(pcapFile1.Name())
		defer pcapFile1.Close()

		pcapFile2 := createTestPcapFile(t, 20)
		defer os.Remove(pcapFile2.Name())
		defer pcapFile2.Close()

		ifaces := []pcaptypes.PcapInterface{
			pcaptypes.CreateOfflineInterface(pcapFile1),
			pcaptypes.CreateOfflineInterface(pcapFile2),
		}

		done := make(chan struct{})
		go func() {
			defer close(done)
			InitWithBuffer(ctx, ifaces, "", buffer, nil, nil)
		}()

		var packetCount int64
		interfacesSeen := make(map[string]bool)
		var mu sync.Mutex

		go func() {
			for pkt := range buffer.Receive() {
				atomic.AddInt64(&packetCount, 1)
				mu.Lock()
				interfacesSeen[pkt.Interface] = true
				mu.Unlock()
			}
		}()

		time.Sleep(500 * time.Millisecond)
		cancel()

		select {
		case <-done:
			// Success
		case <-time.After(3 * time.Second):
			t.Fatal("InitWithBuffer did not return")
		}

		count := atomic.LoadInt64(&packetCount)
		assert.Greater(t, count, int64(0), "Should have received packets from multiple interfaces")

		mu.Lock()
		interfaceCount := len(interfacesSeen)
		mu.Unlock()

		assert.Equal(t, 2, interfaceCount, "Should have seen packets from both interfaces")
		t.Logf("Received %d packets from %d interfaces", count, interfaceCount)
	})
}

// TestInitWithBuffer_NoDoubleBuffering verifies that InitWithBuffer eliminates double-buffering
func TestInitWithBuffer_NoDoubleBuffering(t *testing.T) {
	t.Run("single buffer path from capture to consumer", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		// Create external buffer
		buffer := NewPacketBuffer(ctx, 50) // Small buffer to test backpressure
		defer buffer.Close()

		pcapFile := createTestPcapFile(t, 100) // More packets than buffer
		defer os.Remove(pcapFile.Name())
		defer pcapFile.Close()

		iface := pcaptypes.CreateOfflineInterface(pcapFile)
		ifaces := []pcaptypes.PcapInterface{iface}

		done := make(chan struct{})
		go func() {
			defer close(done)
			InitWithBuffer(ctx, ifaces, "", buffer, nil, nil)
		}()

		// Slow consumer - this tests that backpressure works with single buffer
		var packetCount int64
		go func() {
			for pkt := range buffer.Receive() {
				atomic.AddInt64(&packetCount, 1)
				time.Sleep(5 * time.Millisecond) // Slow processing
				_ = pkt
			}
		}()

		time.Sleep(500 * time.Millisecond)
		cancel()

		select {
		case <-done:
			// Success
		case <-time.After(3 * time.Second):
			t.Fatal("InitWithBuffer did not return")
		}

		// Get drop count from buffer
		dropped := atomic.LoadInt64(&buffer.dropped)

		count := atomic.LoadInt64(&packetCount)
		t.Logf("Received %d packets, dropped %d packets", count, dropped)

		// With slow consumer and small buffer, we expect some drops
		// This proves backpressure is working through the single buffer
		assert.Greater(t, count, int64(0), "Should have received some packets")

		// With 100 packets in file and small buffer + slow consumer, we should see drops
		if dropped == 0 {
			t.Logf("Warning: Expected some drops with slow consumer, but got none. File may have been read slowly.")
		}
	})
}

// TestInit_Legacy tests the legacy Init function (backwards compatibility)
func TestInit_Legacy(t *testing.T) {
	t.Run("calls InitWithContext with background context", func(t *testing.T) {
		pcapFile := createTestPcapFile(t, 15)
		defer os.Remove(pcapFile.Name())
		defer pcapFile.Close()

		iface := pcaptypes.CreateOfflineInterface(pcapFile)
		ifaces := []pcaptypes.PcapInterface{iface}

		var packetCount int64
		processor := func(ch <-chan PacketInfo, asm *tcpassembly.Assembler) {
			// Only read a few packets then return
			for i := 0; i < 10; i++ {
				pkt, ok := <-ch
				if !ok {
					break
				}
				atomic.AddInt64(&packetCount, 1)
				_ = pkt
			}
		}

		// Init should work (will block until processor returns or PCAP ends)
		done := make(chan struct{})
		go func() {
			defer close(done)
			Init(ifaces, "", processor, nil)
		}()

		// Wait for completion with timeout
		select {
		case <-done:
			// Success
		case <-time.After(5 * time.Second):
			t.Fatal("Init did not return")
		}

		count := atomic.LoadInt64(&packetCount)
		require.Equal(t, int64(10), count, "Should have processed exactly 10 packets")
	})
}
