package voip

import (
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewAsyncWriterPool(t *testing.T) {
	pool := NewAsyncWriterPool(4, 100)

	assert.Equal(t, 4, pool.workerCount)
	assert.Equal(t, 100, pool.bufferSize)
	assert.Equal(t, 5*time.Second, pool.workerTimeout)
	assert.NotNil(t, pool.ctx)
	assert.NotNil(t, pool.cancel)
	assert.NotNil(t, pool.writeQueue)
	assert.False(t, pool.started.Load())
	assert.False(t, pool.stopped.Load())
}

func TestAsyncWriterPool_StartStop(t *testing.T) {
	pool := NewAsyncWriterPool(2, 10)

	// Test start
	err := pool.Start()
	require.NoError(t, err)
	assert.True(t, pool.started.Load())

	// Test start again (should be no-op)
	err = pool.Start()
	require.NoError(t, err)

	// Wait a bit to let workers start
	time.Sleep(100 * time.Millisecond)

	// Verify workers are active
	assert.Equal(t, int32(2), pool.stats.WorkersActive.Load())

	// Test stop
	err = pool.Stop()
	require.NoError(t, err)
	assert.True(t, pool.stopped.Load())

	// Test stop again (should be no-op)
	err = pool.Stop()
	require.NoError(t, err)
}

func TestAsyncWriterPool_WritePacketAsync(t *testing.T) {
	// Setup
	ResetConfigOnce()
	pool := NewAsyncWriterPool(2, 10)
	require.NoError(t, pool.Start())
	defer pool.Stop()

	// Create test packet
	packet := createTestPacketForAsync(t)
	callID := "test-call-async"

	// Setup call tracker with a test call
	setupTestCall(t, callID)
	defer cleanupTestCall(callID)

	// Test async write
	err := pool.WritePacketAsync(callID, packet, PacketTypeSIP)
	assert.NoError(t, err)

	// Wait for processing
	time.Sleep(200 * time.Millisecond)

	// Verify statistics
	stats := pool.GetStats()
	assert.Greater(t, stats.PacketsQueued.Load(), int64(0))
}

func TestAsyncWriterPool_WritePacketSync(t *testing.T) {
	// Setup
	ResetConfigOnce()
	pool := NewAsyncWriterPool(2, 10)
	require.NoError(t, pool.Start())
	defer pool.Stop()

	// Create test packet
	packet := createTestPacketForAsync(t)
	callID := "test-call-sync"

	// Setup call tracker with a test call
	setupTestCall(t, callID)
	defer cleanupTestCall(callID)

	// Test sync write
	err := pool.WritePacketSync(callID, packet, PacketTypeSIP)
	assert.NoError(t, err)

	// Verify statistics
	stats := pool.GetStats()
	assert.Greater(t, stats.PacketsQueued.Load(), int64(0))
	assert.Greater(t, stats.PacketsWritten.Load(), int64(0))
}

func TestAsyncWriterPool_QueueFull(t *testing.T) {
	// Setup with very small buffer
	pool := NewAsyncWriterPool(0, 2) // 0 workers to prevent draining
	// Don't start the pool to test queue full behavior

	// Create test packet
	packet := createTestPacketForAsync(t)
	callID := "test-call-full"

	// Setup call tracker
	setupTestCall(t, callID)
	defer cleanupTestCall(callID)

	// Fill the queue to capacity
	err1 := pool.WritePacketAsync(callID, packet, PacketTypeSIP)
	assert.NoError(t, err1) // First should succeed

	err2 := pool.WritePacketAsync(callID, packet, PacketTypeSIP)
	assert.NoError(t, err2) // Second should succeed (buffer size is 2)

	// Third write should fail with queue full
	err3 := pool.WritePacketAsync(callID, packet, PacketTypeSIP)
	assert.Equal(t, ErrQueueFull, err3)

	// Verify queue full statistics
	stats := pool.GetStats()
	assert.Greater(t, stats.QueueFullEvents.Load(), int64(0))
	assert.Greater(t, stats.PacketsDropped.Load(), int64(0))
}

func TestAsyncWriterPool_StoppedWriter(t *testing.T) {
	pool := NewAsyncWriterPool(2, 10)
	pool.stopped.Store(true) // Mark as stopped

	packet := createTestPacketForAsync(t)
	callID := "test-call-stopped"

	// Test writes should fail when stopped
	err := pool.WritePacketAsync(callID, packet, PacketTypeSIP)
	assert.Equal(t, ErrWriterStopped, err)

	err = pool.WritePacketSync(callID, packet, PacketTypeSIP)
	assert.Equal(t, ErrWriterStopped, err)
}

func TestAsyncWriterPool_ConcurrentWrites(t *testing.T) {
	// Setup
	ResetConfigOnce()
	pool := NewAsyncWriterPool(4, 100)
	require.NoError(t, pool.Start())
	defer pool.Stop()

	packet := createTestPacketForAsync(t)
	numGoroutines := 10
	writesPerGoroutine := 20

	// Setup multiple test calls
	callIDs := make([]string, numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		callIDs[i] = "test-call-concurrent-" + string(rune(i))
		setupTestCall(t, callIDs[i])
		defer cleanupTestCall(callIDs[i])
	}

	var wg sync.WaitGroup
	var successCount atomic.Int64

	// Launch concurrent writers
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(callID string) {
			defer wg.Done()
			for j := 0; j < writesPerGoroutine; j++ {
				err := pool.WritePacketAsync(callID, packet, PacketTypeSIP)
				if err == nil {
					successCount.Add(1)
				}
			}
		}(callIDs[i])
	}

	wg.Wait()

	// Wait for processing to complete
	time.Sleep(500 * time.Millisecond)

	// Verify statistics
	stats := pool.GetStats()
	assert.Greater(t, stats.PacketsQueued.Load(), int64(0))
	assert.Greater(t, successCount.Load(), int64(0))
	assert.Equal(t, int32(4), pool.stats.WorkersActive.Load())
}

func TestAsyncWriterPool_InvalidCallID(t *testing.T) {
	// Setup
	ResetConfigOnce()
	pool := NewAsyncWriterPool(2, 10)
	require.NoError(t, pool.Start())
	defer pool.Stop()

	packet := createTestPacketForAsync(t)
	callID := "nonexistent-call"

	// Test write to non-existent call
	err := pool.WritePacketSync(callID, packet, PacketTypeSIP)
	assert.Equal(t, ErrCallNotFound, err)

	// Verify error statistics
	stats := pool.GetStats()
	assert.Greater(t, stats.WriteErrors.Load(), int64(0))
}

func TestAsyncWriterPool_InvalidPacketType(t *testing.T) {
	// Setup
	ResetConfigOnce()
	pool := NewAsyncWriterPool(2, 10)
	require.NoError(t, pool.Start())
	defer pool.Stop()

	packet := createTestPacketForAsync(t)
	callID := "test-call-invalid-type"

	setupTestCall(t, callID)
	defer cleanupTestCall(callID)

	// Test with invalid packet type
	err := pool.WritePacketSync(callID, packet, PacketType(999))
	assert.Equal(t, ErrInvalidPacketType, err)
}

func TestAsyncWriterPool_Statistics(t *testing.T) {
	pool := NewAsyncWriterPool(2, 10)

	// Test initial statistics
	stats := pool.GetStats()
	assert.Equal(t, int64(0), stats.PacketsQueued.Load())
	assert.Equal(t, int64(0), stats.PacketsWritten.Load())
	assert.Equal(t, int64(0), stats.PacketsDropped.Load())
	assert.Equal(t, int64(0), stats.WriteErrors.Load())
	assert.Equal(t, int64(0), stats.QueueFullEvents.Load())
	assert.Equal(t, int64(0), stats.AverageQueueTime.Load())
	assert.Equal(t, int32(0), stats.WorkersActive.Load())
}

func TestAsyncWriterPool_ErrorHandler(t *testing.T) {
	pool := NewAsyncWriterPool(2, 10)

	var receivedCallID string
	var receivedError error
	var errorReceived bool

	// Set custom error handler
	pool.SetErrorHandler(func(callID string, err error) {
		receivedCallID = callID
		receivedError = err
		errorReceived = true
	})

	require.NoError(t, pool.Start())
	defer pool.Stop()

	packet := createTestPacketForAsync(t)
	callID := "test-call-error"

	// Test write with non-existent call (should trigger error)
	pool.WritePacketSync(callID, packet, PacketTypeSIP)

	// Wait for error handling
	time.Sleep(100 * time.Millisecond)

	assert.True(t, errorReceived)
	assert.Equal(t, callID, receivedCallID)
	assert.NotNil(t, receivedError)
}

func TestAsyncWriterPool_SecurityValidation(t *testing.T) {
	// Setup
	ResetConfigOnce()
	pool := NewAsyncWriterPool(2, 10)
	require.NoError(t, pool.Start())
	defer pool.Stop()

	packet := createTestPacketForAsync(t)

	// Test malicious call ID
	maliciousCallID := "../path/traversal/attack"
	setupTestCall(t, maliciousCallID)
	defer cleanupTestCall(maliciousCallID)

	// Write should be rejected due to security validation
	err := pool.WritePacketSync(maliciousCallID, packet, PacketTypeSIP)
	assert.Error(t, err)

	// Verify error statistics
	stats := pool.GetStats()
	assert.Greater(t, stats.WriteErrors.Load(), int64(0))
}

func TestGetAsyncWriter(t *testing.T) {
	// Reset the global async writer to test initialization
	globalAsyncWriter = nil
	asyncWriterOnce = sync.Once{}

	// Reset config for proper initialization
	ResetConfigOnce()

	// Get the global async writer
	writer := GetAsyncWriter()
	assert.NotNil(t, writer)
	assert.True(t, writer.started.Load())

	// Verify singleton behavior
	writer2 := GetAsyncWriter()
	assert.Same(t, writer, writer2)

	// Cleanup
	CloseAsyncWriter()
}

func TestAsyncWriterIntegration_WithUpdatedWriter(t *testing.T) {
	// Reset global state
	globalAsyncWriter = nil
	asyncWriterOnce = sync.Once{}
	ResetConfigOnce()

	packet := createTestPacketForAsync(t)
	callID := "test-integration-call"

	// Setup call
	setupTestCall(t, callID)
	defer cleanupTestCall(callID)

	// Test WriteSIP function (should use async writer)
	WriteSIP(callID, packet)

	// Test WriteRTP function (should use async writer)
	WriteRTP(callID, packet)

	// Wait for async processing
	time.Sleep(200 * time.Millisecond)

	// Get statistics
	stats := GetWriterStats()
	assert.Greater(t, stats.PacketsQueued.Load(), int64(0))

	// Cleanup
	CloseAsyncWriter()
}

// Helper functions for testing

func createTestPacketForAsync(t *testing.T) gopacket.Packet {
	// Create a simple test packet
	eth := &layers.Ethernet{
		SrcMAC:       []byte{0x00, 0x0c, 0x29, 0x1f, 0x3c, 0x4e},
		DstMAC:       []byte{0x00, 0x0c, 0x29, 0x1f, 0x3c, 0x4f},
		EthernetType: layers.EthernetTypeIPv4,
	}

	ip := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    []byte{192, 168, 1, 100},
		DstIP:    []byte{192, 168, 1, 101},
	}

	udp := &layers.UDP{
		SrcPort: 5060,
		DstPort: 5060,
	}
	udp.SetNetworkLayerForChecksum(ip)

	payload := []byte("INVITE sip:test@example.com SIP/2.0\r\nCall-ID: test-call\r\n\r\n")

	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{ComputeChecksums: true}

	err := gopacket.SerializeLayers(buffer, options, eth, ip, udp, gopacket.Payload(payload))
	require.NoError(t, err)

	packet := gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeEthernet, gopacket.Default)

	// Set proper capture info to avoid metadata issues
	packet.Metadata().CaptureInfo.CaptureLength = len(buffer.Bytes())
	packet.Metadata().CaptureInfo.Length = len(buffer.Bytes())
	packet.Metadata().CaptureInfo.Timestamp = time.Now()

	return packet
}

func setupTestCall(t *testing.T, callID string) {
	call := GetOrCreateCall(callID, layers.LinkTypeEthernet)
	require.NotNil(t, call)

	// Initialize the call's writers if they're not already set up
	if call.SIPWriter == nil || call.RTPWriter == nil {
		// Use the existing test helper pattern
		setupTestCallWithWriters(t, callID, call)
	}
}

func setupTestCallWithWriters(t *testing.T, callID string, call *CallInfo) {
	// Create temporary files for testing
	sipFile, err := os.CreateTemp("", "test-sip-*.pcap")
	require.NoError(t, err)

	rtpFile, err := os.CreateTemp("", "test-rtp-*.pcap")
	require.NoError(t, err)

	// Initialize writers
	call.sipFile = sipFile
	call.rtpFile = rtpFile
	call.SIPWriter = pcapgo.NewWriter(sipFile)
	call.RTPWriter = pcapgo.NewWriter(rtpFile)

	// Write headers
	err = call.SIPWriter.WriteFileHeader(65536, layers.LinkTypeEthernet)
	require.NoError(t, err)

	err = call.RTPWriter.WriteFileHeader(65536, layers.LinkTypeEthernet)
	require.NoError(t, err)
}

func cleanupTestCall(callID string) {
	tracker := getTracker()
	tracker.mu.Lock()
	defer tracker.mu.Unlock()

	if call, exists := tracker.callMap[callID]; exists {
		// Clean up temporary files
		if call.sipFile != nil {
			call.sipFile.Close()
			os.Remove(call.sipFile.Name())
		}
		if call.rtpFile != nil {
			call.rtpFile.Close()
			os.Remove(call.rtpFile.Name())
		}
	}

	delete(tracker.callMap, callID)
}

func BenchmarkAsyncWriterPool_WritePacketAsync(b *testing.B) {
	ResetConfigOnce()
	pool := NewAsyncWriterPool(4, 1000)
	pool.Start()
	defer pool.Stop()

	packet := createTestPacketForAsync(&testing.T{})
	callID := "benchmark-call"
	setupTestCall(&testing.T{}, callID)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pool.WritePacketAsync(callID, packet, PacketTypeSIP)
	}
}

func BenchmarkAsyncWriterPool_WritePacketSync(b *testing.B) {
	ResetConfigOnce()
	pool := NewAsyncWriterPool(4, 1000)
	pool.Start()
	defer pool.Stop()

	packet := createTestPacketForAsync(&testing.T{})
	callID := "benchmark-call-sync"
	setupTestCall(&testing.T{}, callID)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pool.WritePacketSync(callID, packet, PacketTypeSIP)
	}
}