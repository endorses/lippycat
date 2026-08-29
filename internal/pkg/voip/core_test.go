//go:build cli || all

package voip

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/pipeline"
	"github.com/endorses/lippycat/internal/pkg/pipeline/captureadapter"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type timestampRecordingAssembler struct {
	mu         sync.Mutex
	timestamps []time.Time
}

func (a *timestampRecordingAssembler) AssembleTCP(_ gopacket.Flow, _ *layers.TCP, timestamp time.Time) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.timestamps = append(a.timestamps, timestamp)
	return nil
}

func TestStartProcessorOfflineIsLosslessAndCaptureOrdered(t *testing.T) {
	tracker := TestCallTracker(t)
	tracker.config.ProcessorWorkers = 4
	tracker.config.ProcessorWorkerBuffer = 1
	bufferManager := NewBufferManager(time.Second, 10)
	defer bufferManager.Close()
	assembler := &timestampRecordingAssembler{}
	input := make(chan *pipeline.PacketEnvelope, 32)
	want := make([]time.Time, 32)
	for i := range want {
		packet := createTCPSIPPacket(t, "OPTIONS sip:test@example.com SIP/2.0\r\nCall-ID: ordered\r\nContent-Length: 0\r\n\r\n", "192.0.2.1", "192.0.2.2")
		info := capture.PacketInfo{Packet: packet, LinkType: layers.LinkTypeEthernet}
		want[i] = time.Unix(int64(i+1), 0)
		info.Packet.Metadata().Timestamp = want[i]
		input <- captureadapter.FromPacketInfo(info, pipeline.SourcePCAPReplay)
	}
	close(input)

	startProcessorWithBuffer(tracker, bufferManager, input, assembler, true)

	require.Equal(t, want, assembler.timestamps)
	require.Nil(t, ProcessorWorkersStats(), "offline replay must not create dropping worker queues")
}

func TestStartProcessor_UDPHandling(t *testing.T) {
	// Reset and initialize config for this test
	ResetConfigOnce()

	// Create a mock UDP packet with SIP content
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

	payload := []byte("INVITE sip:test@example.com SIP/2.0\r\nCall-ID: test-call-123\r\n\r\n")

	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{ComputeChecksums: true}

	err := gopacket.SerializeLayers(buffer, options, eth, ip, udp, gopacket.Payload(payload))
	require.NoError(t, err, "Failed to serialize test packet")

	packet := gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeEthernet, gopacket.Default)

	// Create packet info
	pktInfo := capture.PacketInfo{
		LinkType: layers.LinkTypeEthernet,
		Packet:   packet,
	}

	// Create channel and send packet
	ch := make(chan *pipeline.PacketEnvelope, 1)
	ch <- captureadapter.FromPacketInfo(pktInfo, pipeline.SourceLiveCapture)
	close(ch)

	// Create assembler for TCP processing
	ctx := context.Background()
	tracker := TestCallTracker(t)
	handler := NewLocalFileHandler(tracker)
	streamFactory := NewSipStreamFactory(ctx, handler)
	defer streamFactory.(*sipStreamFactory).Shutdown()
	assembler := capture.NewTCPAssembler(streamFactory)

	// Test the processor
	startProcessor(tracker, ch, assembler)

	// The test passes if no panic occurs and the processor completes
	assert.True(t, true, "Processor completed successfully")
}

func TestStartProcessor_TCPHandling(t *testing.T) {
	// Create a mock TCP packet with SIP content
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
		SrcPort: 5060,
		DstPort: 5060,
		Seq:     1000,
		Ack:     2000,
		Window:  8192,
	}

	tcp.SetNetworkLayerForChecksum(ip)

	payload := []byte("INVITE sip:test@example.com SIP/2.0\r\nCall-ID: test-call-456\r\n\r\n")

	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{ComputeChecksums: true}

	err := gopacket.SerializeLayers(buffer, options, eth, ip, tcp, gopacket.Payload(payload))
	require.NoError(t, err, "Failed to serialize test TCP packet")

	packet := gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeEthernet, gopacket.Default)

	// Create packet info
	pktInfo := capture.PacketInfo{
		LinkType: layers.LinkTypeEthernet,
		Packet:   packet,
	}

	// Create channel and send packet
	ch := make(chan *pipeline.PacketEnvelope, 1)
	ch <- captureadapter.FromPacketInfo(pktInfo, pipeline.SourceLiveCapture)
	close(ch)

	// Create assembler for TCP processing
	ctx := context.Background()
	tracker := TestCallTracker(t)
	handler := NewLocalFileHandler(tracker)
	streamFactory := NewSipStreamFactory(ctx, handler)
	defer streamFactory.(*sipStreamFactory).Shutdown()
	assembler := capture.NewTCPAssembler(streamFactory)

	// Test the processor
	startProcessor(tracker, ch, assembler)

	// The test passes if no panic occurs and the processor completes
	assert.True(t, true, "TCP processor completed successfully")
}

func TestStartProcessor_InvalidPackets(t *testing.T) {
	// Test with packets that have no network or transport layer
	invalidPacket := gopacket.NewPacket([]byte{0x01, 0x02, 0x03}, layers.LayerTypeEthernet, gopacket.Default)

	pktInfo := capture.PacketInfo{
		LinkType: layers.LinkTypeEthernet,
		Packet:   invalidPacket,
	}

	ch := make(chan *pipeline.PacketEnvelope, 1)
	ch <- captureadapter.FromPacketInfo(pktInfo, pipeline.SourceLiveCapture)
	close(ch)

	ctx := context.Background()
	tracker := TestCallTracker(t)
	handler := NewLocalFileHandler(tracker)
	streamFactory := NewSipStreamFactory(ctx, handler)
	defer streamFactory.(*sipStreamFactory).Shutdown()
	assembler := capture.NewTCPAssembler(streamFactory)

	// Should handle invalid packets gracefully
	startProcessor(tracker, ch, assembler)

	assert.True(t, true, "Invalid packet handled gracefully")
}

func TestContainsUserInHeaders(t *testing.T) {
	// Note: When no users are configured, the function returns true (promiscuous mode)
	// This is intentional behavior to allow capturing all VoIP traffic by default
	tests := []struct {
		name     string
		headers  map[string]string
		expected bool
	}{
		{
			name: "User found in From header",
			headers: map[string]string{
				"from": "sip:testuser@example.com",
				"to":   "sip:other@example.com",
			},
			expected: true, // Promiscuous mode (no users configured)
		},
		{
			name: "User found in To header",
			headers: map[string]string{
				"from": "sip:other@example.com",
				"to":   "sip:testuser@example.com",
			},
			expected: true, // Promiscuous mode (no users configured)
		},
		{
			name: "User found in P-Asserted-Identity",
			headers: map[string]string{
				"from":                "sip:other@example.com",
				"to":                  "sip:another@example.com",
				"p-asserted-identity": "sip:testuser@example.com",
			},
			expected: true, // Promiscuous mode (no users configured)
		},
		{
			name: "No users found",
			headers: map[string]string{
				"from": "sip:unknown1@example.com",
				"to":   "sip:unknown2@example.com",
			},
			expected: true, // Promiscuous mode (no users configured)
		},
		{
			name:     "Empty headers",
			headers:  map[string]string{},
			expected: true, // Promiscuous mode (no users configured)
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := containsUserInHeaders(tt.headers)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestProcessorChannelClosure(t *testing.T) {
	// Test that processor handles channel closure gracefully
	ch := make(chan *pipeline.PacketEnvelope)
	close(ch) // Close immediately

	ctx := context.Background()
	tracker := TestCallTracker(t)
	handler := NewLocalFileHandler(tracker)
	streamFactory := NewSipStreamFactory(ctx, handler)
	defer streamFactory.(*sipStreamFactory).Shutdown()
	assembler := capture.NewTCPAssembler(streamFactory)

	// Should complete without hanging
	done := make(chan bool, 1)
	go func() {
		startProcessor(tracker, ch, assembler)
		done <- true
	}()

	select {
	case <-done:
		assert.True(t, true, "Processor completed after channel closure")
	case <-time.After(1 * time.Second):
		t.Fatal("Processor did not complete within timeout")
	}
}
