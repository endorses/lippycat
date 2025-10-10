package detector

import (
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/detector/signatures"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// MockSignature for testing
type MockSignature struct {
	name      string
	protocols []string
	priority  int
	layer     signatures.LayerType
	detectFn  func(*signatures.DetectionContext) *signatures.DetectionResult
}

func (m *MockSignature) Name() string                { return m.name }
func (m *MockSignature) Protocols() []string         { return m.protocols }
func (m *MockSignature) Priority() int               { return m.priority }
func (m *MockSignature) Layer() signatures.LayerType { return m.layer }
func (m *MockSignature) Detect(ctx *signatures.DetectionContext) *signatures.DetectionResult {
	if m.detectFn != nil {
		return m.detectFn(ctx)
	}
	return nil
}

func TestDetector_RegisterSignature(t *testing.T) {
	d := New()

	sig1 := &MockSignature{
		name:      "Test1",
		protocols: []string{"test1"},
		priority:  100,
		layer:     signatures.LayerApplication,
	}

	sig2 := &MockSignature{
		name:      "Test2",
		protocols: []string{"test2"},
		priority:  50,
		layer:     signatures.LayerApplication,
	}

	d.RegisterSignature(sig1)
	d.RegisterSignature(sig2)

	stats := d.GetStats()
	assert.Equal(t, 2, stats["signatures_registered"])

	// Verify priority ordering (sig1 should be first due to higher priority)
	assert.Equal(t, sig1, d.signatures[0])
	assert.Equal(t, sig2, d.signatures[1])
}

func TestDetector_Detect(t *testing.T) {
	d := New()

	// Register a mock signature that detects "TEST" protocol
	d.RegisterSignature(&MockSignature{
		name:      "TestProtocol",
		protocols: []string{"TEST"},
		priority:  100,
		layer:     signatures.LayerApplication,
		detectFn: func(ctx *signatures.DetectionContext) *signatures.DetectionResult {
			if len(ctx.Payload) >= 4 && string(ctx.Payload[:4]) == "TEST" {
				return &signatures.DetectionResult{
					Protocol:    "TEST",
					Confidence:  signatures.ConfidenceVeryHigh,
					Metadata:    map[string]interface{}{"detected": true},
					ShouldCache: true,
				}
			}
			return nil
		},
	})

	// Create a test packet
	packet := createTestPacket([]byte("TEST payload"))

	// Test detection
	result := d.Detect(packet)
	require.NotNil(t, result)
	assert.Equal(t, "TEST", result.Protocol)
	assert.Equal(t, signatures.ConfidenceVeryHigh, result.Confidence)

	// Verify caching (second call should return cached result)
	result2 := d.Detect(packet)
	assert.Equal(t, result.Protocol, result2.Protocol)
}

func TestDetector_PriorityOrdering(t *testing.T) {
	d := New()

	highPriorityCalled := false
	lowPriorityCalled := false

	// High priority signature
	d.RegisterSignature(&MockSignature{
		name:      "HighPriority",
		protocols: []string{"HIGH"},
		priority:  200,
		layer:     signatures.LayerApplication,
		detectFn: func(ctx *signatures.DetectionContext) *signatures.DetectionResult {
			highPriorityCalled = true
			return &signatures.DetectionResult{
				Protocol:    "HIGH",
				Confidence:  signatures.ConfidenceVeryHigh,
				Metadata:    map[string]interface{}{},
				ShouldCache: true,
			}
		},
	})

	// Low priority signature (should never be called)
	d.RegisterSignature(&MockSignature{
		name:      "LowPriority",
		protocols: []string{"LOW"},
		priority:  100,
		layer:     signatures.LayerApplication,
		detectFn: func(ctx *signatures.DetectionContext) *signatures.DetectionResult {
			lowPriorityCalled = true
			return &signatures.DetectionResult{
				Protocol:    "LOW",
				Confidence:  signatures.ConfidenceMedium,
				Metadata:    map[string]interface{}{},
				ShouldCache: true,
			}
		},
	})

	packet := createTestPacket([]byte("test"))
	result := d.Detect(packet)

	assert.True(t, highPriorityCalled, "High priority signature should be called")
	assert.False(t, lowPriorityCalled, "Low priority signature should not be called")
	assert.Equal(t, "HIGH", result.Protocol)
}

func TestDetector_Cache(t *testing.T) {
	d := New()

	callCount := 0

	d.RegisterSignature(&MockSignature{
		name:      "CacheTest",
		protocols: []string{"CACHE"},
		priority:  100,
		layer:     signatures.LayerApplication,
		detectFn: func(ctx *signatures.DetectionContext) *signatures.DetectionResult {
			callCount++
			return &signatures.DetectionResult{
				Protocol:      "CACHE",
				Confidence:    signatures.ConfidenceHigh,
				Metadata:      map[string]interface{}{},
				ShouldCache:   true,
				CacheStrategy: signatures.CacheFlow, // Use CacheFlow to actually cache
			}
		},
	})

	packet := createTestPacket([]byte("cache test"))

	// First call
	d.Detect(packet)
	assert.Equal(t, 1, callCount)

	// Second call (should use cache)
	d.Detect(packet)
	assert.Equal(t, 1, callCount, "Detection function should only be called once due to caching")

	// Clear cache and try again
	d.ClearCache()
	d.Detect(packet)
	assert.Equal(t, 2, callCount, "After cache clear, detection should run again")
}

func TestDetector_FlowTracking(t *testing.T) {
	d := New()

	d.RegisterSignature(&MockSignature{
		name:      "FlowTest",
		protocols: []string{"FLOW"},
		priority:  100,
		layer:     signatures.LayerApplication,
		detectFn: func(ctx *signatures.DetectionContext) *signatures.DetectionResult {
			// Verify flow context exists
			require.NotNil(t, ctx.Flow)
			assert.Equal(t, ctx.FlowID, ctx.Flow.FlowID)

			return &signatures.DetectionResult{
				Protocol:    "FLOW",
				Confidence:  signatures.ConfidenceHigh,
				Metadata:    map[string]interface{}{},
				ShouldCache: false, // Don't cache to test flow tracking
			}
		},
	})

	packet := createTestPacket([]byte("flow test"))

	// First detection
	result1 := d.Detect(packet)
	assert.Equal(t, "FLOW", result1.Protocol)

	// Get flow context
	ctx := d.buildContext(packet)
	flow := d.flows.Get(ctx.FlowID)
	require.NotNil(t, flow)
	assert.Contains(t, flow.Protocols, "FLOW")

	// Second detection (same flow)
	time.Sleep(10 * time.Millisecond)
	result2 := d.Detect(packet)
	assert.Equal(t, "FLOW", result2.Protocol)

	// Verify flow was updated
	flow = d.flows.Get(ctx.FlowID)
	assert.True(t, flow.LastSeen.After(flow.FirstSeen))
}

func TestGenerateFlowID(t *testing.T) {
	tests := []struct {
		name      string
		srcIP     string
		dstIP     string
		srcPort   uint16
		dstPort   uint16
		transport string
	}{
		{
			name:      "Normal order",
			srcIP:     "192.168.1.1",
			dstIP:     "192.168.1.2",
			srcPort:   12345,
			dstPort:   80,
			transport: "TCP",
		},
		{
			name:      "Reverse order (should normalize)",
			srcIP:     "192.168.1.2",
			dstIP:     "192.168.1.1",
			srcPort:   80,
			dstPort:   12345,
			transport: "TCP",
		},
		{
			name:      "UDP transport",
			srcIP:     "10.0.0.1",
			dstIP:     "10.0.0.2",
			srcPort:   5060,
			dstPort:   5060,
			transport: "UDP",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			flowID := generateFlowID(tt.srcIP, tt.dstIP, tt.srcPort, tt.dstPort, tt.transport)
			// Verify it's a hex hash string (16 characters from 64-bit hash)
			assert.Len(t, flowID, 16, "Flow ID should be 16 character hex hash")
			assert.Regexp(t, "^[0-9a-f]{16}$", flowID, "Flow ID should be lowercase hex")
		})
	}

	// Test bidirectional normalization
	flow1 := generateFlowID("192.168.1.1", "192.168.1.2", 12345, 80, "TCP")
	flow2 := generateFlowID("192.168.1.2", "192.168.1.1", 80, 12345, "TCP")
	assert.Equal(t, flow1, flow2, "Bidirectional flows should have same ID")
}

// Helper function to create test packets
func createTestPacket(payload []byte) gopacket.Packet {
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	// Create Ethernet layer
	eth := &layers.Ethernet{
		SrcMAC:       []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
		DstMAC:       []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x02},
		EthernetType: layers.EthernetTypeIPv4,
	}

	// Create IP layer
	ip := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Id:       1234,
		SrcIP:    []byte{192, 168, 1, 1},
		DstIP:    []byte{192, 168, 1, 2},
		Protocol: layers.IPProtocolUDP,
	}

	// Create UDP layer
	udp := &layers.UDP{
		SrcPort: 12345,
		DstPort: 5060,
	}
	_ = udp.SetNetworkLayerForChecksum(ip)

	// Serialize layers with payload
	err := gopacket.SerializeLayers(buf, opts, eth, ip, udp, gopacket.Payload(payload))
	if err != nil {
		panic(err)
	}

	// Create packet from serialized data - use Default for proper decoding
	packet := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
	return packet
}
