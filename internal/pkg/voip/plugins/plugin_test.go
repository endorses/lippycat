package plugins

import (
	"context"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/detector"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSIPPlugin(t *testing.T) {
	plugin := NewSIPPlugin()
	require.NotNil(t, plugin)

	// Test initialization
	err := plugin.Initialize(map[string]interface{}{})
	require.NoError(t, err)

	// Test basic properties
	assert.Equal(t, "SIP Protocol Handler", plugin.Name())
	assert.Equal(t, "1.0.0", plugin.Version())
	assert.Contains(t, plugin.SupportedProtocols(), "sip")

	// Create a mock SIP packet
	sipPayload := `INVITE sip:bob@example.com SIP/2.0
Via: SIP/2.0/UDP 192.168.1.100:5060;branch=z9hG4bK-123456
From: Alice <sip:alice@example.com>;tag=abc123
To: Bob <sip:bob@example.com>
Call-ID: test-call-123@example.com
CSeq: 1 INVITE
Contact: <sip:alice@192.168.1.100:5060>
Content-Type: application/sdp
Content-Length: 142

v=0
o=alice 2890844526 2890844527 IN IP4 192.168.1.100
s=Session Description
c=IN IP4 192.168.1.100
t=0 0
m=audio 49170 RTP/AVP 0`

	packet := createMockPacket([]byte(sipPayload))

	// Test packet processing
	ctx := context.Background()
	result, err := plugin.ProcessPacket(ctx, packet)
	require.NoError(t, err)
	require.NotNil(t, result)

	// Verify result
	assert.Equal(t, "sip", result.Protocol)
	assert.Equal(t, "call_start", result.Action)
	assert.Equal(t, "test-call-123@example.com", result.CallID)
	assert.Greater(t, result.Confidence, 0.9)
	assert.True(t, result.ShouldContinue)

	// Check metadata
	assert.Equal(t, "INVITE", result.Metadata["method"])
	assert.Equal(t, "test-call-123@example.com", result.Metadata["call_id"])

	// Test health check
	health := plugin.HealthCheck()
	assert.Equal(t, HealthHealthy, health.Status)

	// Test metrics
	metrics := plugin.Metrics()
	assert.Equal(t, int64(1), metrics.PacketsProcessed)

	// Test shutdown
	err = plugin.Shutdown(ctx)
	assert.NoError(t, err)
}

func TestRTPPlugin(t *testing.T) {
	plugin := NewRTPPlugin()
	require.NotNil(t, plugin)

	// Test initialization
	err := plugin.Initialize(map[string]interface{}{})
	require.NoError(t, err)

	// Test basic properties
	assert.Equal(t, "RTP Protocol Handler", plugin.Name())
	assert.Equal(t, "1.0.0", plugin.Version())
	assert.Contains(t, plugin.SupportedProtocols(), "rtp")

	// Create a mock RTP packet
	rtpHeader := []byte{
		0x80,       // Version=2, Padding=0, Extension=0, CSRC count=0
		0x00,       // Marker=0, Payload type=0 (PCMU)
		0x00, 0x01, // Sequence number = 1
		0x00, 0x00, 0x00, 0x64, // Timestamp = 100
		0x12, 0x34, 0x56, 0x78, // SSRC = 0x12345678
	}
	rtpPayload := append(rtpHeader, make([]byte, 160)...) // Add some audio payload

	packet := createMockPacket(rtpPayload)

	// Test packet processing
	ctx := context.Background()
	result, err := plugin.ProcessPacket(ctx, packet)
	require.NoError(t, err)
	require.NotNil(t, result)

	// Verify result
	assert.Equal(t, "rtp", result.Protocol)
	assert.Equal(t, "track", result.Action)
	assert.Greater(t, result.Confidence, 0.8)
	assert.True(t, result.ShouldContinue)

	// Check metadata
	assert.Equal(t, uint8(2), result.Metadata["rtp_version"])
	assert.Equal(t, uint8(0), result.Metadata["payload_type"])
	assert.Equal(t, uint16(1), result.Metadata["sequence_number"])
	assert.Equal(t, uint32(100), result.Metadata["timestamp"])
	assert.Equal(t, "audio", result.Metadata["media_type"])

	// Test health check
	health := plugin.HealthCheck()
	assert.Equal(t, HealthHealthy, health.Status)

	// Test metrics
	metrics := plugin.Metrics()
	assert.Equal(t, int64(1), metrics.PacketsProcessed)

	// Test shutdown
	err = plugin.Shutdown(ctx)
	assert.NoError(t, err)
}

func TestGenericPlugin(t *testing.T) {
	plugin := NewGenericPlugin()
	require.NotNil(t, plugin)

	// Test initialization
	err := plugin.Initialize(map[string]interface{}{})
	require.NoError(t, err)

	// Test basic properties
	assert.Equal(t, "Generic Protocol Handler", plugin.Name())
	assert.Equal(t, "1.0.0", plugin.Version())
	assert.Contains(t, plugin.SupportedProtocols(), "generic")

	// Create a mock generic packet
	genericPayload := []byte("Some unknown protocol data")
	packet := createMockPacket(genericPayload)

	// Test packet processing
	ctx := context.Background()
	result, err := plugin.ProcessPacket(ctx, packet)
	require.NoError(t, err)
	require.NotNil(t, result)

	// Verify result
	assert.Equal(t, "generic", result.Protocol)
	assert.Equal(t, "track", result.Action)
	assert.Equal(t, 0.5, result.Confidence) // Lower confidence for generic
	assert.True(t, result.ShouldContinue)

	// Test health check
	health := plugin.HealthCheck()
	assert.Equal(t, HealthHealthy, health.Status)

	// Test shutdown
	err = plugin.Shutdown(ctx)
	assert.NoError(t, err)
}

func TestPluginRegistry(t *testing.T) {
	// Initialize the default detector (required for protocol detection)
	detector.InitDefault()

	registry := NewPluginRegistry()
	require.NotNil(t, registry)

	// Enable registry
	registry.Enable()
	assert.True(t, registry.IsEnabled())

	// Register SIP plugin
	sipPlugin := NewSIPPlugin()
	config := PluginConfig{
		Enabled:  true,
		Priority: 100,
		Timeout:  5 * time.Second,
	}
	err := registry.RegisterPlugin("sip", sipPlugin, config)
	require.NoError(t, err)

	// Test duplicate registration
	err = registry.RegisterPlugin("sip", sipPlugin, config)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "already registered")

	// Test getting plugin
	plugin, exists := registry.GetPlugin("sip")
	assert.True(t, exists)
	assert.NotNil(t, plugin)

	// Test listing plugins
	plugins := registry.ListPlugins()
	assert.Len(t, plugins, 1)
	assert.Contains(t, plugins, "sip")

	// Test getting plugins by protocol
	protocolPlugins := registry.GetPluginsByProtocol("sip")
	assert.Len(t, protocolPlugins, 1)
	assert.Equal(t, "sip", protocolPlugins[0])

	// Test enabling/disabling plugin
	err = registry.DisablePlugin("sip")
	assert.NoError(t, err)

	err = registry.EnablePlugin("sip")
	assert.NoError(t, err)

	// Test health check
	health := registry.HealthCheck()
	assert.Len(t, health, 1)
	assert.Contains(t, health, "sip")

	// Test stats
	stats := registry.GetStats()
	assert.Equal(t, int64(1), stats.TotalPlugins.Load())

	// Test packet processing
	sipPayload := []byte("INVITE sip:test@example.com SIP/2.0\r\nCall-ID: test-123\r\n\r\n")
	packet := createMockPacket(sipPayload)

	ctx := context.Background()
	results, err := registry.ProcessPacket(ctx, packet)
	require.NoError(t, err)
	assert.Len(t, results, 1)

	// Test unregistering plugin
	err = registry.UnregisterPlugin("sip")
	assert.NoError(t, err)

	// Test plugin not found
	_, exists = registry.GetPlugin("sip")
	assert.False(t, exists)

	// Test shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err = registry.Shutdown(ctx)
	assert.NoError(t, err)
}

func TestPluginLoader(t *testing.T) {
	registry := NewPluginRegistry()
	registry.Enable()

	loader := NewPluginLoader(registry)
	require.NotNil(t, loader)

	// Test loading built-in plugins
	err := loader.LoadBuiltinPlugins()
	require.NoError(t, err)

	// Verify plugins were loaded
	plugins := loader.ListLoadedPlugins()
	assert.Len(t, plugins, 3) // SIP, RTP, Generic
	assert.Contains(t, plugins, "sip")
	assert.Contains(t, plugins, "rtp")
	assert.Contains(t, plugins, "generic")

	// Test getting plugin config
	config, err := loader.GetPluginConfig("sip")
	require.NoError(t, err)
	assert.True(t, config.Enabled)
	assert.Equal(t, 100, config.Priority)

	// Test plugin stats
	stats := loader.GetPluginStats()
	assert.Equal(t, 3, stats["total_factories"])

	// Test shutdown
	ctx := context.Background()
	err = loader.Shutdown(ctx)
	assert.NoError(t, err)
}

func TestPluginFactories(t *testing.T) {
	// Test SIP factory
	sipFactory := &SIPPluginFactory{}
	sipPlugin := sipFactory.CreatePlugin()
	assert.NotNil(t, sipPlugin)
	assert.Equal(t, "SIP Protocol Handler", sipPlugin.Name())

	sipInfo := sipFactory.PluginInfo()
	assert.Equal(t, "SIP Protocol Handler", sipInfo.Name)
	assert.Contains(t, sipInfo.Protocols, "sip")

	// Test RTP factory
	rtpFactory := &RTPPluginFactory{}
	rtpPlugin := rtpFactory.CreatePlugin()
	assert.NotNil(t, rtpPlugin)
	assert.Equal(t, "RTP Protocol Handler", rtpPlugin.Name())

	rtpInfo := rtpFactory.PluginInfo()
	assert.Equal(t, "RTP Protocol Handler", rtpInfo.Name)
	assert.Contains(t, rtpInfo.Protocols, "rtp")

	// Test Generic factory
	genericFactory := &GenericPluginFactory{}
	genericPlugin := genericFactory.CreatePlugin()
	assert.NotNil(t, genericPlugin)
	assert.Equal(t, "Generic Protocol Handler", genericPlugin.Name())

	genericInfo := genericFactory.PluginInfo()
	assert.Equal(t, "Generic Protocol Handler", genericInfo.Name)
	assert.Contains(t, genericInfo.Protocols, "generic")
}

func TestDetectProtocols(t *testing.T) {
	// Initialize the default detector (required for centralized detection)
	detector.InitDefault()

	registry := NewPluginRegistry()

	// Test SIP detection
	sipPayload := []byte("INVITE sip:test@example.com SIP/2.0\r\nFrom: <sip:alice@example.com>\r\nTo: <sip:bob@example.com>\r\nCall-ID: test123\r\n\r\n")
	packet := createMockPacket(sipPayload)
	protocols := registry.detectProtocols(packet)
	assert.Contains(t, protocols, "sip")

	// Test RTP detection (valid RTP header: version 2, PT 0, seq 1, timestamp 100, SSRC 0x12345678)
	rtpPayload := []byte{
		0x80,       // V=2, P=0, X=0, CC=0
		0x00,       // M=0, PT=0 (PCMU)
		0x00, 0x01, // Sequence number 1
		0x00, 0x00, 0x00, 0x64, // Timestamp 100
		0x12, 0x34, 0x56, 0x78, // SSRC
		0x00, 0x00, 0x00, 0x00, // Add some payload data (at least 16 bytes total)
	}
	packet = createMockPacketWithPorts(rtpPayload, 10000, 10000) // RTP typically uses high ports
	protocols = registry.detectProtocols(packet)
	assert.Contains(t, protocols, "rtp")

	// Test generic fallback
	unknownPayload := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a} // Binary data
	packet = createMockPacketWithPorts(unknownPayload, 12345, 54321)                     // Non-standard ports
	protocols = registry.detectProtocols(packet)
	assert.Contains(t, protocols, "generic")
}

func TestHealthLevels(t *testing.T) {
	tests := []struct {
		level    HealthLevel
		expected string
	}{
		{HealthHealthy, "healthy"},
		{HealthDegraded, "degraded"},
		{HealthUnhealthy, "unhealthy"},
		{HealthCritical, "critical"},
		{HealthUnknown, "unknown"},
	}

	for _, test := range tests {
		assert.Equal(t, test.expected, test.level.String())
	}
}

func TestEventTypes(t *testing.T) {
	tests := []struct {
		eventType EventType
		expected  string
	}{
		{EventPluginLoaded, "plugin_loaded"},
		{EventPluginUnloaded, "plugin_unloaded"},
		{EventPluginError, "plugin_error"},
		{EventPluginHealthChange, "plugin_health_change"},
		{EventProtocolDetected, "protocol_detected"},
		{EventCallDetected, "call_detected"},
		{EventUnknown, "unknown"},
	}

	for _, test := range tests {
		assert.Equal(t, test.expected, test.eventType.String())
	}
}

// Helper function to create mock packets for testing
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func createMockPacket(payload []byte) gopacket.Packet {
	return createMockPacketWithPorts(payload, 5060, 5060)
}

func createMockPacketWithPorts(payload []byte, srcPort, dstPort uint16) gopacket.Packet {
	// Create a mock packet with the payload as application layer
	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	// Create Ethernet layer
	ethLayer := &layers.Ethernet{
		SrcMAC:       []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05},
		DstMAC:       []byte{0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b},
		EthernetType: layers.EthernetTypeIPv4,
	}

	// Create IP layer
	ipLayer := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Id:       1234,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    []byte{192, 168, 1, 100},
		DstIP:    []byte{192, 168, 1, 200},
	}

	// Create UDP layer
	udpLayer := &layers.UDP{
		SrcPort: layers.UDPPort(srcPort),
		DstPort: layers.UDPPort(dstPort),
	}
	udpLayer.SetNetworkLayerForChecksum(ipLayer)

	// Serialize all layers with payload
	err := gopacket.SerializeLayers(buffer, opts,
		ethLayer,
		ipLayer,
		udpLayer,
		gopacket.Payload(payload),
	)
	if err != nil {
		panic(err)
	}

	// Parse the packet
	packet := gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
	return packet
}

// Benchmark tests
func BenchmarkSIPPluginProcessPacket(b *testing.B) {
	plugin := NewSIPPlugin()
	_ = plugin.Initialize(map[string]interface{}{})

	sipPayload := `INVITE sip:test@example.com SIP/2.0
Call-ID: test-123`
	packet := createMockPacket([]byte(sipPayload))
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := plugin.ProcessPacket(ctx, packet)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkRTPPluginProcessPacket(b *testing.B) {
	plugin := NewRTPPlugin()
	_ = plugin.Initialize(map[string]interface{}{})

	rtpPayload := []byte{0x80, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x64, 0x12, 0x34, 0x56, 0x78}
	rtpPayload = append(rtpPayload, make([]byte, 160)...) // Add payload
	packet := createMockPacket(rtpPayload)
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := plugin.ProcessPacket(ctx, packet)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkPluginRegistryProcessPacket(b *testing.B) {
	registry := NewPluginRegistry()
	registry.Enable()

	// Register plugins
	sipPlugin := NewSIPPlugin()
	config := PluginConfig{Enabled: true, Priority: 100, Timeout: 5 * time.Second}
	registry.RegisterPlugin("sip", sipPlugin, config)

	sipPayload := `INVITE sip:test@example.com SIP/2.0
Call-ID: test-123`
	packet := createMockPacket([]byte(sipPayload))
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := registry.ProcessPacket(ctx, packet)
		if err != nil {
			b.Fatal(err)
		}
	}
}
