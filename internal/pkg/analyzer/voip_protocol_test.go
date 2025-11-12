package analyzer

import (
	"context"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVoIPProtocol_New(t *testing.T) {
	proto := NewVoIPProtocol()
	assert.NotNil(t, proto)
	assert.Equal(t, "VoIP Protocol Analyzer", proto.Name())
	assert.Equal(t, "1.0.0", proto.Version())
	assert.Equal(t, []string{"sip", "rtp", "voip"}, proto.SupportedProtocols())
}

func TestVoIPProtocol_Initialize(t *testing.T) {
	proto := NewVoIPProtocol()

	config := map[string]interface{}{
		"test_key": "test_value",
	}

	err := proto.Initialize(config)
	assert.NoError(t, err)
	assert.True(t, proto.enabled.Load())
}

func TestVoIPProtocol_Shutdown(t *testing.T) {
	proto := NewVoIPProtocol()
	proto.enabled.Store(true)

	ctx := context.Background()
	err := proto.Shutdown(ctx)
	assert.NoError(t, err)
	assert.False(t, proto.enabled.Load())
}

func TestVoIPProtocol_ProcessPacket_SIP(t *testing.T) {
	proto := NewVoIPProtocol()
	proto.enabled.Store(true)

	tests := []struct {
		name       string
		srcPort    layers.UDPPort
		dstPort    layers.UDPPort
		payload    string
		wantResult bool
		wantProto  string
	}{
		{
			name:       "SIP packet on port 5060",
			srcPort:    5060,
			dstPort:    12345,
			payload:    "INVITE sip:user@example.com SIP/2.0\r\nCall-ID: test123@host\r\n",
			wantResult: true,
			wantProto:  "sip",
		},
		{
			name:       "SIP packet on port 5061 (TLS)",
			srcPort:    5061,
			dstPort:    12345,
			payload:    "REGISTER sip:example.com SIP/2.0\r\n",
			wantResult: true,
			wantProto:  "sip",
		},
		{
			name:       "Non-SIP packet",
			srcPort:    8080,
			dstPort:    8081,
			payload:    "HTTP/1.1 200 OK\r\n",
			wantResult: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			packet := createUDPPacket(tt.srcPort, tt.dstPort, []byte(tt.payload))
			result, err := proto.ProcessPacket(context.Background(), packet)

			assert.NoError(t, err)
			if tt.wantResult {
				require.NotNil(t, result)
				assert.Equal(t, tt.wantProto, result.Protocol)
				assert.Greater(t, result.Confidence, 0.0)
				assert.False(t, result.ShouldContinue)
			} else {
				// For non-SIP packets, check if it's RTP range
				if int(tt.srcPort) >= 10000 && int(tt.srcPort) <= 20000 {
					require.NotNil(t, result)
					assert.Equal(t, "rtp", result.Protocol)
				} else if result != nil {
					// Unexpected result
					t.Errorf("Expected nil result for non-SIP/RTP packet, got %+v", result)
				}
			}
		})
	}
}

func TestVoIPProtocol_ProcessPacket_RTP(t *testing.T) {
	proto := NewVoIPProtocol()
	proto.enabled.Store(true)

	tests := []struct {
		name       string
		srcPort    layers.UDPPort
		dstPort    layers.UDPPort
		wantResult bool
	}{
		{
			name:       "RTP packet in range 10000-20000",
			srcPort:    15000,
			dstPort:    15001,
			wantResult: true,
		},
		{
			name:       "RTP packet in range 16384-32767",
			srcPort:    20000,
			dstPort:    20001,
			wantResult: true,
		},
		{
			name:       "Non-RTP packet",
			srcPort:    8080,
			dstPort:    8081,
			wantResult: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			packet := createUDPPacket(tt.srcPort, tt.dstPort, []byte("RTP payload"))
			result, err := proto.ProcessPacket(context.Background(), packet)

			assert.NoError(t, err)
			if tt.wantResult {
				require.NotNil(t, result)
				assert.Equal(t, "rtp", result.Protocol)
				assert.Equal(t, "track", result.Action)
				assert.Greater(t, result.Confidence, 0.0)
			}
		})
	}
}

func TestVoIPProtocol_ProcessPacket_Disabled(t *testing.T) {
	proto := NewVoIPProtocol()
	proto.enabled.Store(false) // Disable the protocol

	packet := createUDPPacket(5060, 5060, []byte("INVITE sip:user@example.com SIP/2.0\r\n"))
	result, err := proto.ProcessPacket(context.Background(), packet)

	assert.NoError(t, err)
	assert.Nil(t, result)
}

func TestVoIPProtocol_ProcessPacket_NonUDP(t *testing.T) {
	proto := NewVoIPProtocol()
	proto.enabled.Store(true)

	// Create a TCP packet (not UDP)
	packet := createTCPPacket(5060, 5060, []byte("test"))
	result, err := proto.ProcessPacket(context.Background(), packet)

	assert.NoError(t, err)
	assert.Nil(t, result) // Should return nil for non-UDP packets
}

func TestVoIPProtocol_HealthCheck(t *testing.T) {
	proto := NewVoIPProtocol()

	// Test when disabled
	proto.enabled.Store(false)
	health := proto.HealthCheck()
	assert.Equal(t, HealthUnhealthy, health.Status)
	assert.Equal(t, "Analyzer disabled", health.Message)

	// Test when enabled
	proto.enabled.Store(true)
	health = proto.HealthCheck()
	assert.Equal(t, HealthHealthy, health.Status)
	assert.Equal(t, "Operating normally", health.Message)
	assert.NotNil(t, health.Details)
	assert.Contains(t, health.Details, "packets_processed")
	assert.Contains(t, health.Details, "sip_packets")
	assert.Contains(t, health.Details, "rtp_packets")
	assert.Contains(t, health.Details, "calls_detected")
}

func TestVoIPProtocol_Metrics(t *testing.T) {
	proto := NewVoIPProtocol()
	proto.enabled.Store(true)

	// Process some packets to generate metrics
	sipPacket := createUDPPacket(5060, 5060, []byte("INVITE sip:user@example.com SIP/2.0\r\n"))
	_, _ = proto.ProcessPacket(context.Background(), sipPacket)

	rtpPacket := createUDPPacket(15000, 15001, []byte("RTP payload"))
	_, _ = proto.ProcessPacket(context.Background(), rtpPacket)

	metrics := proto.Metrics()
	assert.Equal(t, int64(2), metrics.PacketsProcessed)
	assert.Greater(t, metrics.ProcessingTime, time.Duration(0))
	assert.NotNil(t, metrics.CustomMetrics)
	assert.Contains(t, metrics.CustomMetrics, "sip_packets")
	assert.Contains(t, metrics.CustomMetrics, "rtp_packets")
	assert.Contains(t, metrics.CustomMetrics, "calls_detected")

	// Verify SIP and RTP counts
	assert.Equal(t, int64(1), metrics.CustomMetrics["sip_packets"])
	assert.Equal(t, int64(1), metrics.CustomMetrics["rtp_packets"])
}

func TestVoIPProtocol_ProcessPacket_Metrics(t *testing.T) {
	proto := NewVoIPProtocol()
	proto.enabled.Store(true)

	// Process multiple SIP packets
	for i := 0; i < 5; i++ {
		packet := createUDPPacket(5060, 5060, []byte("INVITE sip:user@example.com SIP/2.0\r\n"))
		_, err := proto.ProcessPacket(context.Background(), packet)
		assert.NoError(t, err)
	}

	// Process multiple RTP packets
	for i := 0; i < 10; i++ {
		packet := createUDPPacket(15000, 15001, []byte("RTP payload"))
		_, err := proto.ProcessPacket(context.Background(), packet)
		assert.NoError(t, err)
	}

	// Verify metrics
	assert.Equal(t, int64(15), proto.metrics.packetsProcessed.Load())
	assert.Equal(t, int64(5), proto.metrics.sipPackets.Load())
	assert.Equal(t, int64(10), proto.metrics.rtpPackets.Load())
	assert.Greater(t, proto.metrics.processingTime.Load(), int64(0))
}

func TestVoIPProtocol_ProcessPacket_ContextTimeout(t *testing.T) {
	proto := NewVoIPProtocol()
	proto.enabled.Store(true)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	packet := createUDPPacket(5060, 5060, []byte("INVITE sip:user@example.com SIP/2.0\r\n"))

	// Should complete before timeout (VoIP processing is fast)
	result, err := proto.ProcessPacket(ctx, packet)
	assert.NoError(t, err)
	// Result can be nil or not nil depending on port detection
	if result != nil {
		assert.Equal(t, "sip", result.Protocol)
	}
}

func TestVoIPProtocol_Registration(t *testing.T) {
	// The init() function should have registered the VoIP protocol
	registry := GetRegistry()
	require.NotNil(t, registry)

	// Check if VoIP protocol is registered
	proto, exists := registry.Get("voip")
	assert.True(t, exists)
	assert.NotNil(t, proto)

	// Verify it's a VoIPProtocol
	voipProto, ok := proto.(*VoIPProtocol)
	assert.True(t, ok)
	assert.Equal(t, "VoIP Protocol Analyzer", voipProto.Name())
}

func TestVoIPProtocol_extractCallID(t *testing.T) {
	// Note: extractCallID is currently a stub that returns ""
	// This test documents the expected behavior for future implementation

	tests := []struct {
		name     string
		payload  string
		expected string
	}{
		{
			name:     "empty payload",
			payload:  "",
			expected: "",
		},
		{
			name:     "no Call-ID header",
			payload:  "INVITE sip:user@example.com SIP/2.0\r\n",
			expected: "",
		},
		// Future tests when extractCallID is implemented:
		// {
		//     name:     "valid Call-ID",
		//     payload:  "INVITE sip:user@example.com SIP/2.0\r\nCall-ID: test123@host\r\n",
		//     expected: "test123@host",
		// },
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractCallID(tt.payload)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// Helper functions

func createUDPPacket(srcPort, dstPort layers.UDPPort, payload []byte) gopacket.Packet {
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	ip := &layers.IPv4{
		SrcIP:    []byte{192, 168, 1, 1},
		DstIP:    []byte{192, 168, 1, 2},
		Protocol: layers.IPProtocolUDP,
		Version:  4,
		TTL:      64,
	}

	udp := &layers.UDP{
		SrcPort: srcPort,
		DstPort: dstPort,
	}
	udp.SetNetworkLayerForChecksum(ip)

	gopacket.SerializeLayers(buf, opts, ip, udp, gopacket.Payload(payload))
	return gopacket.NewPacket(buf.Bytes(), layers.LayerTypeIPv4, gopacket.Default)
}

func createTCPPacket(srcPort, dstPort layers.TCPPort, payload []byte) gopacket.Packet {
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	ip := &layers.IPv4{
		SrcIP:    []byte{192, 168, 1, 1},
		DstIP:    []byte{192, 168, 1, 2},
		Protocol: layers.IPProtocolTCP,
		Version:  4,
		TTL:      64,
	}

	tcp := &layers.TCP{
		SrcPort: srcPort,
		DstPort: dstPort,
		Seq:     1,
		Ack:     0,
		Window:  65535,
		SYN:     true,
	}
	tcp.SetNetworkLayerForChecksum(ip)

	gopacket.SerializeLayers(buf, opts, ip, tcp, gopacket.Payload(payload))
	return gopacket.NewPacket(buf.Bytes(), layers.LayerTypeIPv4, gopacket.Default)
}
