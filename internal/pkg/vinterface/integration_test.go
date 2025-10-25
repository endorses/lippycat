//go:build integration
// +build integration

package vinterface

import (
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestIntegration_SniffToVirtualInterface tests the complete flow:
// sniff command → virtual interface → tcpdump
//
// This test requires:
// - CAP_NET_ADMIN capability or root privileges
// - /dev/net/tun access
//
// Run with: go test -tags=integration -v ./internal/pkg/vinterface/... -run TestIntegration
func TestIntegration_SniffToVirtualInterface(t *testing.T) {
	// Skip if not running as root or with CAP_NET_ADMIN
	if !hasNetAdminCapability() {
		t.Skip("Test requires CAP_NET_ADMIN capability or root privileges")
	}

	// Create manager with default config
	cfg := DefaultConfig()
	cfg.Name = "lc-test0" // Use unique name to avoid conflicts
	mgr, err := NewManager(cfg)
	require.NoError(t, err)

	// Start the virtual interface
	err = mgr.Start()
	require.NoError(t, err)
	defer mgr.Shutdown()

	// Give interface time to come up
	time.Sleep(100 * time.Millisecond)

	// Create test packets
	packets := []types.PacketDisplay{
		{
			SrcIP:    "192.168.1.100",
			DstIP:    "192.168.1.200",
			SrcPort:  "5060",
			DstPort:  "5061",
			Protocol: "UDP",
			Info:     "SIP INVITE",
			LinkType: layers.LinkTypeEthernet,
		},
		{
			SrcIP:    "192.168.1.200",
			DstIP:    "192.168.1.100",
			SrcPort:  "5061",
			DstPort:  "5060",
			Protocol: "UDP",
			Info:     "SIP 200 OK",
			LinkType: layers.LinkTypeEthernet,
		},
	}

	// Inject packets
	err = mgr.InjectPacketBatch(packets)
	require.NoError(t, err)

	// Give injection time to complete
	time.Sleep(100 * time.Millisecond)

	// Check stats
	stats := mgr.Stats()
	assert.GreaterOrEqual(t, stats.PacketsInjected, uint64(2), "Should have injected at least 2 packets")
	assert.Equal(t, uint64(0), stats.PacketsDropped, "Should have no drops")
	assert.Greater(t, stats.BytesInjected, uint64(0), "Should have injected bytes")
}

// TestIntegration_ProcessToVirtualInterface tests distributed mode:
// hunter → processor → virtual interface
func TestIntegration_ProcessToVirtualInterface(t *testing.T) {
	if !hasNetAdminCapability() {
		t.Skip("Test requires CAP_NET_ADMIN capability or root privileges")
	}

	cfg := DefaultConfig()
	cfg.Name = "lc-proc-test0"
	mgr, err := NewManager(cfg)
	require.NoError(t, err)

	err = mgr.Start()
	require.NoError(t, err)
	defer mgr.Shutdown()

	// Simulate packets from hunter
	packets := generateTestPackets(100)

	// Inject in batches
	for i := 0; i < len(packets); i += 10 {
		end := i + 10
		if end > len(packets) {
			end = len(packets)
		}
		err = mgr.InjectPacketBatch(packets[i:end])
		require.NoError(t, err)
	}

	time.Sleep(100 * time.Millisecond)

	stats := mgr.Stats()
	assert.GreaterOrEqual(t, stats.PacketsInjected, uint64(100), "Should have injected 100 packets")
	assert.Equal(t, uint64(0), stats.ConversionErrors, "Should have no conversion errors")
}

// TestIntegration_TUNInterface tests TUN (Layer 3) interface
func TestIntegration_TUNInterface(t *testing.T) {
	if !hasNetAdminCapability() {
		t.Skip("Test requires CAP_NET_ADMIN capability or root privileges")
	}

	cfg := DefaultConfig()
	cfg.Name = "lc-tun-test0"
	cfg.Type = "tun"
	mgr, err := NewManager(cfg)
	require.NoError(t, err)

	err = mgr.Start()
	require.NoError(t, err)
	defer mgr.Shutdown()

	// TUN interfaces expect IP packets (no Ethernet header)
	packets := []types.PacketDisplay{
		{
			SrcIP:    "10.0.0.1",
			DstIP:    "10.0.0.2",
			SrcPort:  "5060",
			DstPort:  "5060",
			Protocol: "UDP",
			Info:     "RTP",
			LinkType: layers.LinkTypeRaw, // Raw IP
		},
	}

	err = mgr.InjectPacketBatch(packets)
	require.NoError(t, err)

	time.Sleep(100 * time.Millisecond)

	stats := mgr.Stats()
	assert.GreaterOrEqual(t, stats.PacketsInjected, uint64(1))
}

// TestIntegration_QueueOverflow tests behavior when queue is full
func TestIntegration_QueueOverflow(t *testing.T) {
	if !hasNetAdminCapability() {
		t.Skip("Test requires CAP_NET_ADMIN capability or root privileges")
	}

	// Create manager with very small buffer
	cfg := DefaultConfig()
	cfg.Name = "lc-overflow-test0"
	cfg.BufferSize = 10 // Very small buffer
	mgr, err := NewManager(cfg)
	require.NoError(t, err)

	err = mgr.Start()
	require.NoError(t, err)
	defer mgr.Shutdown()

	// Flood with many packets quickly
	packets := generateTestPackets(1000)
	err = mgr.InjectPacketBatch(packets)
	require.NoError(t, err)

	time.Sleep(200 * time.Millisecond)

	stats := mgr.Stats()
	// With a small buffer, we expect some drops
	assert.Greater(t, stats.PacketsDropped, uint64(0), "Should have dropped some packets due to overflow")
	assert.Greater(t, stats.PacketsInjected, uint64(0), "Should have injected some packets")
}

// TestIntegration_MultipleInterfaces tests creating multiple virtual interfaces
func TestIntegration_MultipleInterfaces(t *testing.T) {
	if !hasNetAdminCapability() {
		t.Skip("Test requires CAP_NET_ADMIN capability or root privileges")
	}

	// Create first interface
	cfg1 := DefaultConfig()
	cfg1.Name = "lc-multi-test1"
	mgr1, err := NewManager(cfg1)
	require.NoError(t, err)

	err = mgr1.Start()
	require.NoError(t, err)
	defer mgr1.Shutdown()

	// Create second interface
	cfg2 := DefaultConfig()
	cfg2.Name = "lc-multi-test2"
	mgr2, err := NewManager(cfg2)
	require.NoError(t, err)

	err = mgr2.Start()
	require.NoError(t, err)
	defer mgr2.Shutdown()

	// Inject to both
	packets := generateTestPackets(10)
	err = mgr1.InjectPacketBatch(packets)
	require.NoError(t, err)
	err = mgr2.InjectPacketBatch(packets)
	require.NoError(t, err)

	time.Sleep(100 * time.Millisecond)

	stats1 := mgr1.Stats()
	stats2 := mgr2.Stats()
	assert.GreaterOrEqual(t, stats1.PacketsInjected, uint64(10))
	assert.GreaterOrEqual(t, stats2.PacketsInjected, uint64(10))
}

// Helper functions

func generateTestPackets(count int) []types.PacketDisplay {
	packets := make([]types.PacketDisplay, count)
	for i := 0; i < count; i++ {
		packets[i] = types.PacketDisplay{
			SrcIP:    "192.168.1.100",
			DstIP:    "192.168.1.200",
			SrcPort:  "5060",
			DstPort:  "5060",
			Protocol: "UDP",
			Info:     "Test packet",
			LinkType: layers.LinkTypeEthernet,
		}
	}
	return packets
}

func hasNetAdminCapability() bool {
	// Try to create a test interface to check for CAP_NET_ADMIN
	cfg := DefaultConfig()
	cfg.Name = "lc-cap-check"
	mgr, err := NewManager(cfg)
	if err != nil {
		return false
	}

	err = mgr.Start()
	if err != nil {
		return false
	}

	mgr.Shutdown()
	return true
}
