package voip

import (
	"context"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/tcpassembly"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewSipStreamFactory(t *testing.T) {
	ctx := context.Background()
	factory := NewSipStreamFactory(ctx, NewLocalFileHandler())
	assert.NotNil(t, factory, "NewSipStreamFactory should return a non-nil factory")
}

func TestSipStreamFactoryNew(t *testing.T) {
	ctx := context.Background()
	factory := NewSipStreamFactory(ctx, NewLocalFileHandler())

	// Create mock network and transport flows
	var netFlow, transportFlow gopacket.Flow

	// Test creating a new stream
	stream := factory.New(netFlow, transportFlow)
	assert.NotNil(t, stream, "Factory.New should return a non-nil stream")

	// The function should return a tcpreader.ReaderStream, test that it's usable
	// We can't test much more without access to private implementation
	assert.NotNil(t, stream)
}

func TestCallIDDetector_Concurrency(t *testing.T) {
	detector := NewCallIDDetector()
	defer detector.Close()

	const numGoroutines = 50
	const expectedCallID = "first-call-id"

	var startWg sync.WaitGroup
	var endWg sync.WaitGroup

	// Start multiple goroutines that try to set the call ID
	for i := 0; i < numGoroutines; i++ {
		startWg.Add(1)
		endWg.Add(1)
		go func(id int) {
			defer endWg.Done()
			startWg.Done()
			startWg.Wait() // Wait for all goroutines to start

			callID := fmt.Sprintf("call-id-%d", id)
			if id == 0 {
				callID = expectedCallID // First goroutine gets the expected ID
			}
			detector.SetCallID(callID)
		}(i)
	}

	// Start goroutines that wait for the result
	results := make(chan string, numGoroutines)
	for i := 0; i < numGoroutines/10; i++ { // Fewer waiters to avoid blocking
		endWg.Add(1)
		go func() {
			defer endWg.Done()
			result := detector.Wait()
			results <- result
		}()
	}

	endWg.Wait()
	close(results)

	// Verify only one call ID was set (should be the first one)
	uniqueResults := make(map[string]int)
	for result := range results {
		uniqueResults[result]++
	}

	assert.Len(t, uniqueResults, 1, "Only one call ID should be set")

	// The result should be one of the attempted call IDs
	for callID := range uniqueResults {
		assert.NotEmpty(t, callID, "Call ID should not be empty")
	}
}

func TestCallIDDetector_Wait_Timeout(t *testing.T) {
	// Skip by default as this test takes 30 seconds
	// Set LIPPYCAT_LONG_TESTS=1 to enable
	if os.Getenv("LIPPYCAT_LONG_TESTS") != "1" {
		t.Skip("Skipping 30-second timeout test (set LIPPYCAT_LONG_TESTS=1 to enable)")
	}

	detector := NewCallIDDetector()
	defer detector.Close()

	// Test waiting with timeout when no call ID is set
	start := time.Now()
	result := detector.Wait()
	duration := time.Since(start)

	// Should timeout after approximately 30 seconds (but we'll accept 29-31s for timing variance)
	assert.GreaterOrEqual(t, duration, 29*time.Second, "Wait should timeout after ~30 seconds")
	assert.LessOrEqual(t, duration, 31*time.Second, "Wait should not take much longer than 30 seconds")
	assert.Empty(t, result, "Should return empty string on timeout")
}

func TestCallIDDetector_SetCallID_Multiple(t *testing.T) {
	detector := NewCallIDDetector()
	defer detector.Close()

	firstCallID := "first-call-id"
	secondCallID := "second-call-id"

	// Set first call ID
	detector.SetCallID(firstCallID)

	// Try to set second call ID (should be ignored)
	detector.SetCallID(secondCallID)

	// Wait should return the first call ID
	result := detector.Wait()
	assert.Equal(t, firstCallID, result, "Should return first call ID, subsequent calls should be ignored")
}

func TestCallIDDetector_Close_Before_Set(t *testing.T) {
	detector := NewCallIDDetector()

	// Close before setting
	detector.Close()

	// Try to set call ID after close (should be ignored)
	detector.SetCallID("test-call-id")

	// Wait should return empty string quickly
	start := time.Now()
	result := detector.Wait()
	duration := time.Since(start)

	assert.Less(t, duration, 1*time.Second, "Wait should return quickly after close")
	assert.Empty(t, result, "Should return empty string when closed before set")
}

func TestSipStreamFactory_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	factory := NewSipStreamFactory(ctx, NewLocalFileHandler())

	// Create a stream
	var netFlow, transportFlow gopacket.Flow
	stream := factory.New(netFlow, transportFlow)
	assert.NotNil(t, stream, "Should create stream before cancellation")

	// Cancel the context
	cancel()

	// Creating new streams should still work (factory doesn't prevent it)
	// but the streams should handle context cancellation internally
	stream2 := factory.New(netFlow, transportFlow)
	assert.NotNil(t, stream2, "Should still create stream after cancellation")

	// Close the factory
	if closer, ok := factory.(*sipStreamFactory); ok {
		closer.Close()
	}
}

func TestSipStreamFactory_MultipleStreams(t *testing.T) {
	ctx := context.Background()
	factory := NewSipStreamFactory(ctx, NewLocalFileHandler())
	defer func() {
		if closer, ok := factory.(*sipStreamFactory); ok {
			closer.Close()
		}
	}()

	const numStreams = 100
	streams := make([]tcpassembly.Stream, numStreams)

	// Create multiple streams concurrently
	var wg sync.WaitGroup
	for i := 0; i < numStreams; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			var netFlow, transportFlow gopacket.Flow
			stream := factory.New(netFlow, transportFlow)
			streams[idx] = stream
		}(i)
	}

	wg.Wait()

	// Verify all streams were created
	for i, stream := range streams {
		assert.NotNil(t, stream, "Stream %d should be created", i)
	}
}

func TestHandleTcpPackets_Integration(t *testing.T) {
	// Create a TCP packet with SIP content on port 5060
	eth := &layers.Ethernet{
		SrcMAC:       []byte{0x00, 0x0c, 0x29, 0x1f, 0x3c, 0x4e},
		DstMAC:       []byte{0x00, 0x0c, 0x29, 0x1f, 0x3c, 0x4f},
		EthernetType: layers.EthernetTypeIPv4,
	}

	ip := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    []byte{192, 168, 1, 100},
		DstIP:    []byte{192, 168, 1, 101},
	}

	tcp := &layers.TCP{
		SrcPort: 5060, // SIP port
		DstPort: 1234,
		Seq:     1000,
		Ack:     2000,
		Window:  8192,
		SYN:     true,
	}
	tcp.SetNetworkLayerForChecksum(ip)

	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{ComputeChecksums: true}

	err := gopacket.SerializeLayers(buffer, options, eth, ip, tcp)
	require.NoError(t, err, "Failed to serialize TCP packet")

	packet := gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
	pktInfo := capture.PacketInfo{
		LinkType: layers.LinkTypeEthernet,
		Packet:   packet,
	}

	// Create assembler
	ctx := context.Background()
	streamFactory := NewSipStreamFactory(ctx, NewLocalFileHandler())
	streamPool := tcpassembly.NewStreamPool(streamFactory)
	assembler := tcpassembly.NewAssembler(streamPool)

	// Test that handleTcpPackets doesn't panic
	tcpLayer := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)
	assert.NotPanics(t, func() {
		handleTcpPackets(pktInfo, tcpLayer, assembler)
	}, "handleTcpPackets should not panic with valid SIP TCP packet")

	// Clean up
	if closer, ok := streamFactory.(*sipStreamFactory); ok {
		closer.Close()
	}
}

func TestHandleTcpPackets_NonSipPort(t *testing.T) {
	// Create a TCP packet on a non-SIP port (should be ignored)
	eth := &layers.Ethernet{
		SrcMAC:       []byte{0x00, 0x0c, 0x29, 0x1f, 0x3c, 0x4e},
		DstMAC:       []byte{0x00, 0x0c, 0x29, 0x1f, 0x3c, 0x4f},
		EthernetType: layers.EthernetTypeIPv4,
	}

	ip := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    []byte{192, 168, 1, 100},
		DstIP:    []byte{192, 168, 1, 101},
	}

	tcp := &layers.TCP{
		SrcPort: 8080, // Non-SIP port
		DstPort: 8081, // Non-SIP port
		Seq:     1000,
		Ack:     2000,
		Window:  8192,
	}
	tcp.SetNetworkLayerForChecksum(ip)

	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{ComputeChecksums: true}

	err := gopacket.SerializeLayers(buffer, options, eth, ip, tcp)
	require.NoError(t, err, "Failed to serialize TCP packet")

	packet := gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
	pktInfo := capture.PacketInfo{
		LinkType: layers.LinkTypeEthernet,
		Packet:   packet,
	}

	// Create assembler
	ctx := context.Background()
	streamFactory := NewSipStreamFactory(ctx, NewLocalFileHandler())
	streamPool := tcpassembly.NewStreamPool(streamFactory)
	assembler := tcpassembly.NewAssembler(streamPool)

	// Should handle non-SIP packets gracefully (essentially ignore them)
	tcpLayer := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)
	assert.NotPanics(t, func() {
		handleTcpPackets(pktInfo, tcpLayer, assembler)
	}, "handleTcpPackets should handle non-SIP ports gracefully")

	// Clean up
	if closer, ok := streamFactory.(*sipStreamFactory); ok {
		closer.Close()
	}
}

// Phase 3 Performance Optimization Tests

func TestTCPBufferStats(t *testing.T) {
	// Reset stats for test
	tcpBufferStats = &tcpBufferStatsInternal{
		lastStatsUpdate: time.Now(),
	}
	// Also clear the buffer map
	tcpPacketBuffersMu.Lock()
	tcpPacketBuffers = make(map[gopacket.Flow]*TCPPacketBuffer)
	tcpPacketBuffersMu.Unlock()

	stats := GetTCPBufferStats()
	assert.Equal(t, int64(0), stats.TotalBuffers)
	assert.Equal(t, int64(0), stats.TotalPackets)
	assert.Equal(t, int64(0), stats.BuffersDropped)
	// PacketsDropped field was removed, use BuffersDropped instead
}

func TestTCPStreamMetrics(t *testing.T) {
	// Reset metrics for test
	tcpStreamMetrics = &tcpStreamMetricsInternal{
		lastMetricsUpdate: time.Now(),
	}

	metrics := GetTCPStreamMetrics()
	assert.Equal(t, int64(0), metrics.ActiveStreams)
	assert.Equal(t, int64(0), metrics.TotalStreamsCreated)
	assert.Equal(t, int64(0), metrics.TotalStreamsCompleted)
	assert.Equal(t, int64(0), metrics.TotalStreamsFailed)
}

func TestTCPBufferStrategies(t *testing.T) {
	tests := []struct {
		name     string
		strategy string
		maxSize  int
		packets  int
		expected int
	}{
		{
			name:     "fixed strategy - drops when full",
			strategy: "fixed",
			maxSize:  3,
			packets:  5,
			expected: 3,
		},
		{
			name:     "ring strategy - overwrites oldest",
			strategy: "ring",
			maxSize:  3,
			packets:  5,
			expected: 3,
		},
		{
			name:     "adaptive strategy - removes 25% when full",
			strategy: "adaptive",
			maxSize:  4,
			packets:  6,
			expected: 4,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create test buffer
			buffer := getOrCreateBuffer(tt.strategy, tt.maxSize)
			require.NotNil(t, buffer)
			assert.Equal(t, tt.strategy, buffer.strategy)
			assert.Equal(t, tt.maxSize, buffer.maxSize)

			// Create test packets
			testPackets := make([]capture.PacketInfo, tt.packets)
			for i := 0; i < tt.packets; i++ {
				testPackets[i] = capture.PacketInfo{
					Packet: createTestPacket(t, layers.LayerTypeEthernet),
				}
			}

			// Simulate packet buffering based on strategy
			for _, pkt := range testPackets {
				switch tt.strategy {
				case "ring":
					if len(buffer.packets) >= buffer.maxSize {
						buffer.packets[0] = pkt
						buffer.packets = append(buffer.packets[1:], buffer.packets[0])
					} else {
						buffer.packets = append(buffer.packets, pkt)
					}
				case "adaptive":
					if len(buffer.packets) >= buffer.maxSize {
						removeCount := buffer.maxSize / 4
						if removeCount < 1 {
							removeCount = 1
						}
						buffer.packets = buffer.packets[removeCount:]
					}
					buffer.packets = append(buffer.packets, pkt)
				default: // "fixed"
					if len(buffer.packets) >= buffer.maxSize {
						buffer.packets = buffer.packets[1:]
					}
					buffer.packets = append(buffer.packets, pkt)
				}
			}

			assert.LessOrEqual(t, len(buffer.packets), tt.expected)
			releaseBuffer(buffer)
		})
	}
}

func TestTCPBufferPool(t *testing.T) {
	// Save original pool state
	originalPool := tcpBufferPool
	defer func() {
		tcpBufferPool = originalPool
	}()

	// Reset pool for test
	tcpBufferPool = &TCPBufferPool{
		buffers: make([]*TCPPacketBuffer, 0, 10),
		maxSize: 10,
	}

	// Reset atomic counters
	atomic.StoreInt64(&bufferCreationCount, 0)
	atomic.StoreInt64(&bufferReuseCount, 0)
	atomic.StoreInt64(&bufferReleaseCount, 0)

	// Test buffer creation
	buffer1 := getOrCreateBuffer("adaptive", 100)
	require.NotNil(t, buffer1)
	assert.Equal(t, int64(1), atomic.LoadInt64(&bufferCreationCount))

	// Test buffer release
	releaseBuffer(buffer1)
	assert.Equal(t, int64(1), atomic.LoadInt64(&bufferReleaseCount))
	assert.Equal(t, 1, len(tcpBufferPool.buffers))

	// Test buffer reuse
	buffer2 := getOrCreateBuffer("fixed", 200)
	require.NotNil(t, buffer2)
	assert.Equal(t, buffer1, buffer2) // Should be the same buffer
	assert.Equal(t, int64(1), atomic.LoadInt64(&bufferReuseCount))
	assert.Equal(t, "fixed", buffer2.strategy)
	assert.Equal(t, 200, buffer2.maxSize)
}

func TestPerformanceModeOptimizations(t *testing.T) {
	tests := []struct {
		name             string
		mode             string
		expectedBatch    int
		expectedStrategy string
	}{
		{
			name:             "throughput mode",
			mode:             "throughput",
			expectedBatch:    64,
			expectedStrategy: "ring",
		},
		{
			name:             "latency mode",
			mode:             "latency",
			expectedBatch:    1,
			expectedStrategy: "fixed",
		},
		{
			name:             "memory mode",
			mode:             "memory",
			expectedBatch:    32, // uses default
			expectedStrategy: "adaptive",
		},
		{
			name:             "balanced mode",
			mode:             "balanced",
			expectedBatch:    32,         // uses default
			expectedStrategy: "adaptive", // uses default
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &Config{
				TCPPerformanceMode: tt.mode,
				TCPBatchSize:       32,         // default
				TCPBufferStrategy:  "adaptive", // default
				MaxGoroutines:      1000,       // default
			}

			applyPerformanceModeOptimizations(config)

			assert.Equal(t, tt.expectedBatch, config.TCPBatchSize)
			assert.Equal(t, tt.expectedStrategy, config.TCPBufferStrategy)

			switch tt.mode {
			case "throughput":
				assert.Equal(t, 2000, config.MaxGoroutines)
			case "memory":
				assert.Equal(t, 100, config.MaxGoroutines)
				assert.True(t, config.MemoryOptimization)
			case "latency":
				assert.True(t, config.TCPLatencyOptimization)
			}
		})
	}
}

func TestDetectCallIDHeader(t *testing.T) {
	tests := []struct {
		name     string
		line     string
		expected string
		valid    bool
	}{
		{
			name:     "full form call-id",
			line:     "Call-ID: 1234567890@example.com",
			expected: "1234567890@example.com",
			valid:    true,
		},
		{
			name:     "compact form call-id",
			line:     "i: call-123-abc",
			expected: "call-123-abc",
			valid:    true,
		},
		{
			name:     "case insensitive",
			line:     "call-id: UPPER-CASE-ID",
			expected: "UPPER-CASE-ID",
			valid:    true,
		},
		{
			name:     "with extra spaces",
			line:     "Call-ID:   spaced-call-id   ",
			expected: "spaced-call-id",
			valid:    true,
		},
		{
			name:     "not a call-id header",
			line:     "Via: SIP/2.0/TCP example.com",
			expected: "",
			valid:    false,
		},
		{
			name:     "empty call-id",
			line:     "Call-ID: ",
			expected: "",
			valid:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var callID string
			valid := detectCallIDHeader(tt.line, &callID)
			assert.Equal(t, tt.valid, valid)
			assert.Equal(t, tt.expected, callID)
		})
	}
}

func TestParseContentLength(t *testing.T) {
	tests := []struct {
		name     string
		value    string
		expected int
	}{
		{
			name:     "valid number",
			value:    "123",
			expected: 123,
		},
		{
			name:     "zero",
			value:    "0",
			expected: 0,
		},
		{
			name:     "with whitespace",
			value:    "  456  ",
			expected: 456,
		},
		{
			name:     "invalid characters",
			value:    "123abc",
			expected: 123,
		},
		{
			name:     "no numbers",
			value:    "abc",
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseContentLength(tt.value)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestSipStreamFactoryHealthChecks(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ResetConfigOnce()
	config := GetConfig()
	config.MaxGoroutines = 10
	config.StreamQueueBuffer = 5
	config.TCPCleanupInterval = 100 * time.Millisecond

	factory := NewSipStreamFactory(ctx, NewLocalFileHandler()).(*sipStreamFactory)
	defer factory.Close()

	// Test initial healthy state
	assert.True(t, factory.IsHealthy())

	// Test health status details
	status := factory.GetHealthStatus()
	healthy, ok := status["healthy"].(bool)
	require.True(t, ok)
	assert.True(t, healthy)

	activeGoroutines, ok := status["active_goroutines"].(int64)
	require.True(t, ok)
	assert.Equal(t, int64(0), activeGoroutines)

	queueLength, ok := status["queue_length"].(int)
	require.True(t, ok)
	assert.Equal(t, 0, queueLength)
}

func TestGlobalTCPAssemblerMonitoring(t *testing.T) {
	// Reset global state for test isolation
	ResetTestState()
	defer ResetTestState() // Clean up after test

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Test with no factory registered
	health := GetTCPAssemblerHealth()
	require.NotNil(t, health)
	status, ok := health["status"].(string)
	require.True(t, ok)
	assert.Equal(t, "not_initialized", status)

	healthy := IsTCPAssemblerHealthy()
	assert.False(t, healthy)

	// Register a factory
	factory := NewSipStreamFactory(ctx, NewLocalFileHandler()).(*sipStreamFactory)
	defer factory.Close()

	// Now health should be available
	health = GetTCPAssemblerHealth()
	require.NotNil(t, health)
	healthy, ok = health["healthy"].(bool)
	require.True(t, ok)
	assert.True(t, healthy)

	// Test comprehensive metrics
	metrics := GetTCPAssemblerMetrics()
	require.NotNil(t, metrics)
	assert.Contains(t, metrics, "health")
	assert.Contains(t, metrics, "buffers")
	assert.Contains(t, metrics, "streams")
	assert.Contains(t, metrics, "timestamp")
}

// Helper function to create test packets
func createTestPacket(t *testing.T, linkType gopacket.LayerType) gopacket.Packet {
	t.Helper()

	var buf gopacket.SerializeBuffer = gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{}

	// Create a minimal packet based on link type
	switch linkType {
	case layers.LayerTypeEthernet:
		eth := &layers.Ethernet{
			SrcMAC:       []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05},
			DstMAC:       []byte{0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b},
			EthernetType: layers.EthernetTypeIPv4,
		}
		err := gopacket.SerializeLayers(buf, opts, eth)
		require.NoError(t, err)
	default:
		// Create a minimal raw packet
		bytes := buf.Bytes()
		copy(bytes, []byte{0x00, 0x01, 0x02, 0x03})
	}

	return gopacket.NewPacket(buf.Bytes(), linkType, gopacket.Default)
}

// Helper function to reset config for testing
func ResetConfigOnce() {
	configOnce = sync.Once{}
}

// ResetTestState resets all global state for test isolation
func ResetTestState() {
	// Reset config
	configOnce = sync.Once{}

	// Reset global TCP factory
	globalTCPMutex.Lock()
	globalTCPFactory = nil
	globalTCPMutex.Unlock()
}
