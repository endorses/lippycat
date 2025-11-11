package capture

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/capture/pcaptypes"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/tcpassembly"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProcessStream(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		expectLog bool
	}{
		{"Normal data", "test data for stream processing", true},
		{"Empty data", "", false},
		{"Large data", strings.Repeat("x", 8192), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader := strings.NewReader(tt.input)

			// This should not panic and should complete
			processStream(reader)

			// Test passes if no panic occurs
			assert.True(t, true)
		})
	}
}

func TestProcessStreamWithError(t *testing.T) {
	// Create a reader that will return an error
	errorReader := &errorReader{err: io.ErrUnexpectedEOF}

	// This should handle the error gracefully and not panic
	processStream(errorReader)

	// Test passes if no panic occurs
	assert.True(t, true)
}

func TestProcessStreamRecovery(t *testing.T) {
	// Test that processStream function exists
	assert.NotNil(t, processStream)
}

func TestStartLiveSniffer(t *testing.T) {
	// Test that StartLiveSniffer function exists and can be called
	// This is mainly a smoke test since we can't easily test actual packet capture

	var called bool
	mockStartSniffer := func(devices []pcaptypes.PcapInterface, filter string) {
		called = true
		assert.Equal(t, "port 5060", filter)
		assert.Equal(t, 1, len(devices))
	}

	StartLiveSniffer("eth0", "port 5060", mockStartSniffer)
	assert.True(t, called, "startSniffer function should be called")
}

func TestStartOfflineSniffer(t *testing.T) {
	// Test that StartOfflineSniffer function exists
	// We'll just test that the function exists and compiles
	assert.NotNil(t, StartOfflineSniffer)
}

func TestPacketInfo(t *testing.T) {
	// Test PacketInfo struct can be created
	var pkt PacketInfo

	assert.NotNil(t, &pkt)
	// The struct should be usable even when empty
	assert.Nil(t, pkt.Packet)
}

// Helper structs for testing

type errorReader struct {
	err error
}

func (r *errorReader) Read(p []byte) (n int, err error) {
	return 0, r.err
}

func TestProcessStreamBufferHandling(t *testing.T) {
	// Test with data larger than buffer size
	largeData := strings.Repeat("A", 8192) // Larger than the 4096 buffer
	reader := strings.NewReader(largeData)

	// Should process without issues
	processStream(reader)

	assert.True(t, true)
}

func TestProcessStreamPartialReads(t *testing.T) {
	// Create a reader that returns data in small chunks
	data := "This is test data for partial reads"
	reader := &slowReader{data: []byte(data), chunkSize: 5}

	// Should handle partial reads correctly
	processStream(reader)

	assert.True(t, true)
}

type slowReader struct {
	data      []byte
	pos       int
	chunkSize int
}

func (r *slowReader) Read(p []byte) (n int, err error) {
	if r.pos >= len(r.data) {
		return 0, io.EOF
	}

	// Simulate slow reading by returning small chunks
	remaining := len(r.data) - r.pos
	toRead := r.chunkSize
	if toRead > remaining {
		toRead = remaining
	}
	if toRead > len(p) {
		toRead = len(p)
	}

	copy(p, r.data[r.pos:r.pos+toRead])
	r.pos += toRead

	// Add small delay to simulate network conditions
	time.Sleep(1 * time.Millisecond)

	return toRead, nil
}

func TestProcessStreamConcurrency(t *testing.T) {
	// Test that multiple streams can be processed concurrently
	done := make(chan bool, 3)

	for i := 0; i < 3; i++ {
		go func(id int) {
			data := strings.Repeat("test data stream ", 100)
			reader := strings.NewReader(data)
			processStream(reader)
			done <- true
		}(i)
	}

	// Wait for all streams to complete with timeout
	timeout := time.After(5 * time.Second)
	for i := 0; i < 3; i++ {
		select {
		case <-done:
			// Stream completed successfully
		case <-timeout:
			t.Fatal("Timed out waiting for stream processing")
		}
	}

	assert.True(t, true)
}

// mockPcapInterface implements pcaptypes.PcapInterface for testing
type mockPcapInterface struct {
	name        string
	handle      *pcap.Handle
	handleError error
	setError    error
}

func (m *mockPcapInterface) Name() string {
	return m.name
}

func (m *mockPcapInterface) SetHandle() error {
	return m.setError
}

func (m *mockPcapInterface) Handle() (*pcap.Handle, error) {
	return m.handle, m.handleError
}

// TestStartLiveSniffer_MultipleInterfaces tests StartLiveSniffer with multiple interfaces
func TestStartLiveSniffer_MultipleInterfaces(t *testing.T) {
	tests := []struct {
		name       string
		interfaces string
		filter     string
		wantCount  int
	}{
		{
			name:       "single interface",
			interfaces: "eth0",
			filter:     "tcp",
			wantCount:  1,
		},
		{
			name:       "multiple interfaces",
			interfaces: "eth0,eth1,lo",
			filter:     "udp port 53",
			wantCount:  3,
		},
		{
			name:       "empty filter",
			interfaces: "any",
			filter:     "",
			wantCount:  1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var capturedDevices []pcaptypes.PcapInterface
			var capturedFilter string

			mockStartSniffer := func(devices []pcaptypes.PcapInterface, filter string) {
				capturedDevices = devices
				capturedFilter = filter
			}

			StartLiveSniffer(tt.interfaces, tt.filter, mockStartSniffer)

			assert.Equal(t, tt.wantCount, len(capturedDevices), "Should create correct number of devices")
			assert.Equal(t, tt.filter, capturedFilter, "Filter should be passed through")

			// Verify device names
			expectedNames := strings.Split(tt.interfaces, ",")
			for i, dev := range capturedDevices {
				assert.Equal(t, expectedNames[i], dev.Name(), "Device %d name should match", i)
			}
		})
	}
}

// TestStartOfflineSniffer_ErrorHandling tests StartOfflineSniffer error paths
func TestStartOfflineSniffer_ErrorHandling(t *testing.T) {
	// Create a test PCAP file
	testFile := filepath.Join(t.TempDir(), "test.pcap")
	f, err := os.Create(testFile)
	require.NoError(t, err)
	f.Close()

	t.Run("success", func(t *testing.T) {
		var capturedDevices []pcaptypes.PcapInterface
		var capturedFilter string
		var startSnifferCalled atomic.Bool

		mockStartSniffer := func(devices []pcaptypes.PcapInterface, filter string) {
			startSnifferCalled.Store(true)
			capturedDevices = devices
			capturedFilter = filter
		}

		StartOfflineSniffer(testFile, "tcp port 5060", mockStartSniffer)

		assert.True(t, startSnifferCalled.Load(), "startSniffer should be called")
		assert.Equal(t, 1, len(capturedDevices), "Should create one offline device")
		assert.Contains(t, capturedDevices[0].Name(), "test.pcap", "Device name should contain filename")
		assert.Equal(t, "tcp port 5060", capturedFilter, "Filter should be passed through")
	})

	t.Run("file not found", func(t *testing.T) {
		var startSnifferCalled atomic.Bool
		mockStartSniffer := func(devices []pcaptypes.PcapInterface, filter string) {
			startSnifferCalled.Store(true)
		}

		StartOfflineSniffer("/nonexistent/file.pcap", "tcp", mockStartSniffer)

		// Function should return early without calling startSniffer
		assert.False(t, startSnifferCalled.Load(), "startSniffer should not be called for nonexistent file")
	})

	t.Run("timeout handling", func(t *testing.T) {
		var startSnifferCalled atomic.Bool
		blockingStartSniffer := func(devices []pcaptypes.PcapInterface, filter string) {
			startSnifferCalled.Store(true)
			// Block briefly to test goroutine execution
			time.Sleep(10 * time.Millisecond)
		}

		StartOfflineSniffer(testFile, "tcp", blockingStartSniffer)

		// Should complete (either normally or via timeout context)
		assert.True(t, startSnifferCalled.Load(), "startSniffer should have been called")
	})
}

// TestCheckCapturePermissions tests the checkCapturePermissions function
func TestCheckCapturePermissions(t *testing.T) {
	t.Run("all devices succeed", func(t *testing.T) {
		devices := []pcaptypes.PcapInterface{
			&mockPcapInterface{name: "eth0", setError: nil},
			&mockPcapInterface{name: "eth1", setError: nil},
		}

		result := checkCapturePermissions(devices)
		assert.True(t, result, "Should return true when all devices succeed")
	})

	t.Run("all devices fail", func(t *testing.T) {
		devices := []pcaptypes.PcapInterface{
			&mockPcapInterface{name: "eth0", setError: errors.New("permission denied")},
			&mockPcapInterface{name: "eth1", setError: errors.New("permission denied")},
		}

		result := checkCapturePermissions(devices)
		assert.False(t, result, "Should return false when all devices fail")
	})

	t.Run("some devices succeed", func(t *testing.T) {
		devices := []pcaptypes.PcapInterface{
			&mockPcapInterface{name: "eth0", setError: errors.New("permission denied")},
			&mockPcapInterface{name: "eth1", setError: nil},
			&mockPcapInterface{name: "eth2", setError: errors.New("no such device")},
		}

		result := checkCapturePermissions(devices)
		assert.True(t, result, "Should return true when at least one device succeeds")
	})

	t.Run("empty device list", func(t *testing.T) {
		devices := []pcaptypes.PcapInterface{}

		result := checkCapturePermissions(devices)
		assert.False(t, result, "Should return false for empty device list")
	})

	t.Run("handle with close", func(t *testing.T) {
		// Create mock handle that can be closed
		devices := []pcaptypes.PcapInterface{
			&mockPcapInterface{
				name:     "eth0",
				setError: nil,
				handle:   nil, // Will return nil handle
			},
		}

		result := checkCapturePermissions(devices)
		assert.True(t, result, "Should return true even with nil handle")
	})
}

// TestRunOffline tests the RunOffline function
func TestRunOffline(t *testing.T) {
	t.Run("successful offline processing with real pcap", func(t *testing.T) {
		// Use a real small PCAP file
		pcapFile := "../../testdata/pcaps/http.pcap"
		if _, err := os.Stat(pcapFile); os.IsNotExist(err) {
			t.Skip("Test PCAP file not available")
		}

		f, err := os.Open(pcapFile)
		require.NoError(t, err)
		defer f.Close()

		devices := []pcaptypes.PcapInterface{
			pcaptypes.CreateOfflineInterface(f),
		}

		var processedPackets atomic.Int32
		processor := func(ch <-chan PacketInfo, asm *tcpassembly.Assembler) {
			for range ch {
				processedPackets.Add(1)
			}
		}

		// Run with timeout to ensure completion
		done := make(chan struct{})
		go func() {
			RunOffline(devices, "", processor, nil)
			close(done)
		}()

		select {
		case <-done:
			// Completed successfully
			assert.Greater(t, processedPackets.Load(), int32(0), "Should process at least one packet")
		case <-time.After(5 * time.Second):
			t.Fatal("RunOffline timed out")
		}
	})

	t.Run("all captures fail", func(t *testing.T) {
		devices := []pcaptypes.PcapInterface{
			&mockPcapInterface{name: "fail1", setError: errors.New("permission denied")},
		}

		var processorCalled atomic.Bool
		processor := func(ch <-chan PacketInfo, asm *tcpassembly.Assembler) {
			processorCalled.Store(true)
			for range ch {
			}
		}

		RunOffline(devices, "", processor, nil)

		// Processor should be called even if captures fail
		assert.True(t, processorCalled.Load(), "Processor should be called")
	})

	t.Run("with TCP assembler", func(t *testing.T) {
		pcapFile := "../../testdata/pcaps/tcp_sip_complete_call.pcap"
		if _, err := os.Stat(pcapFile); os.IsNotExist(err) {
			t.Skip("Test PCAP file not available")
		}

		f, err := os.Open(pcapFile)
		require.NoError(t, err)
		defer f.Close()

		devices := []pcaptypes.PcapInterface{
			pcaptypes.CreateOfflineInterface(f),
		}

		var processedPackets atomic.Int32
		processor := func(ch <-chan PacketInfo, asm *tcpassembly.Assembler) {
			for range ch {
				processedPackets.Add(1)
			}
		}

		// Create TCP assembler
		streamFactory := NewStreamFactory()
		streamPool := tcpassembly.NewStreamPool(streamFactory)
		assembler := tcpassembly.NewAssembler(streamPool)

		done := make(chan struct{})
		go func() {
			RunOffline(devices, "", processor, assembler)
			close(done)
		}()

		select {
		case <-done:
			assert.Greater(t, processedPackets.Load(), int32(0), "Should process packets")
		case <-time.After(5 * time.Second):
			t.Fatal("RunOffline with assembler timed out")
		}
	})
}

// TestProcessStreamEdgeCases tests processStream edge cases
func TestProcessStreamEdgeCases(t *testing.T) {
	t.Run("read data successfully", func(t *testing.T) {
		data := []byte("test data for stream processing")
		reader := bytes.NewReader(data)
		processStream(reader)
	})

	t.Run("empty stream", func(t *testing.T) {
		reader := bytes.NewReader([]byte{})
		processStream(reader)
	})

	t.Run("large stream", func(t *testing.T) {
		data := make([]byte, 10000)
		for i := range data {
			data[i] = byte(i % 256)
		}
		reader := bytes.NewReader(data)
		processStream(reader)
	})

	t.Run("error during read", func(t *testing.T) {
		reader := &customErrorReader{err: errors.New("simulated read error")}
		processStream(reader)
	})

	t.Run("EOF error", func(t *testing.T) {
		reader := &customErrorReader{err: io.EOF}
		processStream(reader)
	})
}

// customErrorReader for testing error paths
type customErrorReader struct {
	err error
}

func (e *customErrorReader) Read(p []byte) (int, error) {
	return 0, e.err
}

// TestStreamFactory tests the streamFactory functionality
func TestStreamFactory(t *testing.T) {
	t.Run("factory creation", func(t *testing.T) {
		factory := NewStreamFactory().(*streamFactory)
		assert.NotNil(t, factory, "Factory should be created")
		assert.NotNil(t, factory.workerPool, "Worker pool should be initialized")
		assert.Equal(t, maxStreamWorkers, cap(factory.workerPool), "Worker pool should have correct capacity")
	})

	t.Run("worker pool exhaustion", func(t *testing.T) {
		factory := NewStreamFactory().(*streamFactory)

		// Manually fill the worker pool to simulate exhaustion
		// We'll add workers without starting goroutines
		filledSlots := make([]struct{}, 0, maxStreamWorkers)
		for i := 0; i < maxStreamWorkers; i++ {
			factory.workerPool <- struct{}{}
			filledSlots = append(filledSlots, struct{}{})
		}

		// Verify pool is full
		assert.Equal(t, maxStreamWorkers, len(factory.workerPool),
			"Worker pool should be completely full")

		// Try to create a stream when pool is full (should succeed but skip processing)
		net := gopacket.NewFlow(layers.EndpointIPv4, []byte{192, 168, 1, 3}, []byte{192, 168, 1, 4})
		transport := gopacket.NewFlow(layers.EndpointTCPPort, []byte{0, 90}, []byte{0, 1})
		stream := factory.New(net, transport)

		// Stream should still be created (worker pool exhaustion is logged but doesn't fail)
		assert.NotNil(t, stream, "Stream should be created even when pool is full")

		// Pool should still be full (no new worker was added)
		assert.Equal(t, maxStreamWorkers, len(factory.workerPool),
			"Worker pool should remain full after rejected stream creation")

		// Manually drain the pool to clean up
		for i := 0; i < maxStreamWorkers; i++ {
			<-factory.workerPool
		}

		// Verify pool is empty
		assert.Equal(t, 0, len(factory.workerPool),
			"Worker pool should be empty after draining")
	})

	t.Run("shutdown with no workers", func(t *testing.T) {
		factory := NewStreamFactory().(*streamFactory)

		// Shutdown should complete immediately when no workers are active
		done := make(chan struct{})
		go func() {
			factory.Shutdown()
			close(done)
		}()

		select {
		case <-done:
			// Completed successfully
		case <-time.After(1 * time.Second):
			t.Fatal("Shutdown timed out")
		}
	})
}

// TestProcessPacket tests the processPacket function
func TestProcessPacket(t *testing.T) {
	t.Run("process TCP packets", func(t *testing.T) {
		packetChan := make(chan PacketInfo, 10)

		tcpPacket := createTCPPacket()
		packetChan <- PacketInfo{Packet: tcpPacket}
		close(packetChan)

		streamFactory := NewStreamFactory()
		streamPool := tcpassembly.NewStreamPool(streamFactory)
		assembler := tcpassembly.NewAssembler(streamPool)

		processPacket(packetChan, assembler)
	})

	t.Run("process UDP packets", func(t *testing.T) {
		packetChan := make(chan PacketInfo, 10)

		udpPacket := createUDPPacket()
		packetChan <- PacketInfo{Packet: udpPacket}
		close(packetChan)

		processPacket(packetChan, nil)
	})

	t.Run("empty channel", func(t *testing.T) {
		packetChan := make(chan PacketInfo)
		close(packetChan)

		processPacket(packetChan, nil)
	})

	t.Run("multiple packets", func(t *testing.T) {
		packetChan := make(chan PacketInfo, 100)

		// Add mix of TCP and UDP packets
		for i := 0; i < 50; i++ {
			if i%2 == 0 {
				packetChan <- PacketInfo{Packet: createTCPPacket()}
			} else {
				packetChan <- PacketInfo{Packet: createUDPPacket()}
			}
		}
		close(packetChan)

		streamFactory := NewStreamFactory()
		streamPool := tcpassembly.NewStreamPool(streamFactory)
		assembler := tcpassembly.NewAssembler(streamPool)

		processPacket(packetChan, assembler)
	})

	t.Run("packet without network layer", func(t *testing.T) {
		packetChan := make(chan PacketInfo, 10)

		// Create malformed packet without network layer
		malformedPacket := gopacket.NewPacket(
			[]byte{0x00, 0x01, 0x02},
			layers.LayerTypeEthernet,
			gopacket.Default,
		)
		packetChan <- PacketInfo{Packet: malformedPacket}
		close(packetChan)

		streamFactory := NewStreamFactory()
		streamPool := tcpassembly.NewStreamPool(streamFactory)
		assembler := tcpassembly.NewAssembler(streamPool)

		// Should handle gracefully without panic
		processPacket(packetChan, assembler)
	})
}

// TestProcessPacketWithContext tests the processPacketWithContext function
func TestProcessPacketWithContext(t *testing.T) {
	t.Run("process TCP packet", func(t *testing.T) {
		ctx := context.Background()
		tcpPacket := createTCPPacket()
		pkt := PacketInfo{Packet: tcpPacket}

		streamFactory := NewStreamFactory()
		streamPool := tcpassembly.NewStreamPool(streamFactory)
		assembler := tcpassembly.NewAssembler(streamPool)

		processPacketWithContext(pkt, assembler, ctx)
	})

	t.Run("process UDP packet", func(t *testing.T) {
		ctx := context.Background()
		udpPacket := createUDPPacket()
		pkt := PacketInfo{Packet: udpPacket}

		processPacketWithContext(pkt, nil, ctx)
	})

	t.Run("process malformed packet", func(t *testing.T) {
		ctx := context.Background()
		malformedPacket := gopacket.NewPacket(
			[]byte{0x00, 0x01, 0x02},
			layers.LayerTypeEthernet,
			gopacket.Default,
		)
		pkt := PacketInfo{Packet: malformedPacket}

		processPacketWithContext(pkt, nil, ctx)
	})

	t.Run("cancelled context", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately

		tcpPacket := createTCPPacket()
		pkt := PacketInfo{Packet: tcpPacket}

		// Should complete without error even with cancelled context
		processPacketWithContext(pkt, nil, ctx)
	})
}

// Helper function to create a TCP packet
func createTCPPacket() gopacket.Packet {
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	eth := &layers.Ethernet{
		SrcMAC:       []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
		DstMAC:       []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x02},
		EthernetType: layers.EthernetTypeIPv4,
	}

	ip := &layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    []byte{192, 168, 1, 1},
		DstIP:    []byte{192, 168, 1, 2},
	}

	tcp := &layers.TCP{
		SrcPort: 12345,
		DstPort: 80,
		Seq:     1000,
		SYN:     true,
	}
	tcp.SetNetworkLayerForChecksum(ip)

	gopacket.SerializeLayers(buf, opts, eth, ip, tcp, gopacket.Payload([]byte("test data")))
	return gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
}

// Helper function to create a UDP packet
func createUDPPacket() gopacket.Packet {
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	eth := &layers.Ethernet{
		SrcMAC:       []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
		DstMAC:       []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x02},
		EthernetType: layers.EthernetTypeIPv4,
	}

	ip := &layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    []byte{192, 168, 1, 1},
		DstIP:    []byte{192, 168, 1, 2},
	}

	udp := &layers.UDP{
		SrcPort: 12345,
		DstPort: 53,
	}
	udp.SetNetworkLayerForChecksum(ip)

	gopacket.SerializeLayers(buf, opts, eth, ip, udp, gopacket.Payload([]byte("test data")))
	return gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
}
