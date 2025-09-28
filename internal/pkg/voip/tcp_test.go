package voip

import (
	"context"
	"fmt"
	"sync"
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
	factory := NewSipStreamFactory(ctx)
	assert.NotNil(t, factory, "NewSipStreamFactory should return a non-nil factory")
}

func TestSipStreamFactoryNew(t *testing.T) {
	ctx := context.Background()
	factory := NewSipStreamFactory(ctx)

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
	factory := NewSipStreamFactory(ctx)

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
	factory := NewSipStreamFactory(ctx)
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
	streamFactory := NewSipStreamFactory(ctx)
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
	streamFactory := NewSipStreamFactory(ctx)
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
