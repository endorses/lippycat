package capture

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/capture/pcaptypes"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/tcpassembly"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestStartLiveSniffer_ErrorHandling tests error handling in live sniffer startup
func TestStartLiveSniffer_ErrorHandling(t *testing.T) {
	tests := []struct {
		name         string
		interfaces   string
		filter       string
		mockBehavior string
		description  string
	}{
		{
			name:        "Empty interface string",
			interfaces:  "",
			filter:      "port 5060",
			description: "Should handle empty interface string gracefully",
		},
		{
			name:        "Single interface",
			interfaces:  "eth0",
			filter:      "port 5060",
			description: "Should handle single interface",
		},
		{
			name:        "Multiple interfaces",
			interfaces:  "eth0,wlan0,lo",
			filter:      "udp",
			description: "Should handle multiple interfaces",
		},
		{
			name:        "Interfaces with whitespace",
			interfaces:  " eth0 , wlan0 , lo ",
			filter:      "",
			description: "Should handle interfaces with whitespace",
		},
		{
			name:        "Invalid BPF filter syntax",
			interfaces:  "eth0",
			filter:      "invalid filter syntax {{{",
			description: "Should handle invalid BPF filter",
		},
		{
			name:        "Very long filter",
			interfaces:  "eth0",
			filter:      "host 192.168.1.1 and port 5060 and (tcp or udp) and " + generateLongFilter(),
			description: "Should handle very long BPF filters",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Mock the startSniffer function to avoid actual network operations
			called := false
			mockStartSniffer := func(devices []pcaptypes.PcapInterface, filter string) {
				called = true
				// Validate that devices were created correctly
				expectedDeviceCount := 1 // At least one device should be created
				if tt.interfaces != "" {
					expectedDeviceCount = len(splitAndTrimInterfaces(tt.interfaces))
				}
				assert.Equal(t, expectedDeviceCount, len(devices), "Device count should match")
			}

			// Should not panic
			assert.NotPanics(t, func() {
				StartLiveSniffer(tt.interfaces, tt.filter, mockStartSniffer)
			}, tt.description)

			assert.True(t, called, "StartSniffer should be called")
		})
	}
}

func TestStartOfflineSniffer_FileHandling(t *testing.T) {
	tests := []struct {
		name        string
		setupFile   func(*testing.T) string
		filter      string
		expectError bool
		description string
	}{
		{
			name: "Valid empty file",
			setupFile: func(t *testing.T) string {
				tmpFile := t.TempDir() + "/empty.pcap"
				// Create empty file
				file, err := os.Create(tmpFile)
				require.NoError(t, err)
				file.Close()
				return tmpFile
			},
			filter:      "port 5060",
			expectError: false, // Empty files should be handled gracefully
			description: "Should handle empty PCAP files",
		},
		{
			name: "Relative path",
			setupFile: func(t *testing.T) string {
				return "./nonexistent.pcap"
			},
			filter:      "",
			expectError: true,
			description: "Should handle relative paths appropriately",
		},
		{
			name: "Path with special characters",
			setupFile: func(t *testing.T) string {
				return "/tmp/file with spaces & special chars!.pcap"
			},
			filter:      "udp",
			expectError: true, // File doesn't exist
			description: "Should handle paths with special characters",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filePath := tt.setupFile(t)

			// Mock startSniffer to avoid file operations that would cause log.Fatal
			mockStartSniffer := func(devices []pcaptypes.PcapInterface, filter string) {
				// Just verify we got called with the right parameters
				assert.Equal(t, tt.filter, filter)
				assert.Len(t, devices, 1, "Should create one device for offline capture")
			}

			// Note: This test may not fully exercise error paths due to log.Fatal calls
			// in the actual implementation, but it verifies the parameter handling
			if !tt.expectError {
				assert.NotPanics(t, func() {
					StartOfflineSniffer(filePath, tt.filter, mockStartSniffer)
				}, tt.description)
			}
		})
	}
}

func TestPacketBuffer_SecurityAndStress(t *testing.T) {
	ctx := context.Background()

	t.Run("Buffer overflow protection", func(t *testing.T) {
		buffer := NewPacketBuffer(ctx, 5) // Small buffer
		defer buffer.Close()

		// Try to send more packets than buffer can hold
		packets := make([]PacketInfo, 20)
		for i := range packets {
			packets[i] = createTestPacket()
		}

		sentCount := 0
		for _, pkt := range packets {
			if buffer.Send(pkt) {
				sentCount++
			}
		}

		// Should not accept more than buffer size when no receiver
		assert.LessOrEqual(t, sentCount, 5, "Should not accept more packets than buffer size")
	})

	t.Run("Receiver backpressure", func(t *testing.T) {
		buffer := NewPacketBuffer(ctx, 10)
		defer buffer.Close()

		// Start slow receiver
		ch := buffer.Receive()
		go func() {
			for pkt := range ch {
				// Slow processing
				time.Sleep(10 * time.Millisecond)
				_ = pkt
			}
		}()

		// Send packets quickly
		successCount := 0
		for i := 0; i < 100; i++ {
			pkt := createTestPacket()
			if buffer.Send(pkt) {
				successCount++
			}
		}

		// Some sends should fail due to backpressure
		assert.Greater(t, successCount, 0, "Should send some packets")
		assert.Less(t, successCount, 100, "Should experience backpressure")
	})

	t.Run("Malformed packet handling", func(t *testing.T) {
		buffer := NewPacketBuffer(ctx, 10)
		defer buffer.Close()

		// Create malformed packet
		malformedPacket := PacketInfo{
			Packet:   nil, // Nil packet
			LinkType: layers.LinkTypeEthernet,
		}

		// Should handle nil packets gracefully
		assert.NotPanics(t, func() {
			buffer.Send(malformedPacket)
		}, "Should handle nil packets gracefully")
	})
}

func TestCaptureFromInterface_ErrorScenarios(t *testing.T) {
	// Test what we can test without calling log.Fatal functions

	t.Run("Mock interface error handling", func(t *testing.T) {
		ctx := context.Background()
		mockDevice := &MockPcapInterface{name: "mock0"}

		// Test that mock device properly returns errors
		_, err := mockDevice.Handle()
		assert.Error(t, err, "Mock interface should return error from Handle()")

		// Test packet buffer creation
		packetBuffer := NewPacketBuffer(ctx, 10)
		assert.NotNil(t, packetBuffer, "PacketBuffer should be created")

		// Test that the mock has expected properties
		assert.Equal(t, "mock0", mockDevice.Name(), "Mock name should be set correctly")

		// Test SetHandle method
		setErr := mockDevice.SetHandle()
		assert.NoError(t, setErr, "SetHandle should not error for mock")

		// Cleanup
		packetBuffer.Close()
	})
}

func TestInit_ComponentIntegration(t *testing.T) {
	t.Run("PacketBuffer creation", func(t *testing.T) {
		// Test that PacketBuffer is created properly
		ctx := context.Background()
		buffer := NewPacketBuffer(ctx, 100)

		assert.NotNil(t, buffer, "PacketBuffer should not be nil")

		// Test that we can close the buffer properly
		buffer.Close()
	})

	t.Run("Stream factory setup", func(t *testing.T) {
		// Test that stream factory can be created
		streamFactory := &MockStreamFactory{}
		streamPool := tcpassembly.NewStreamPool(streamFactory)
		assembler := tcpassembly.NewAssembler(streamPool)

		assert.NotNil(t, streamPool, "Stream pool should not be nil")
		assert.NotNil(t, assembler, "Assembler should not be nil")
	})
}

// Helper functions and mocks

func generateLongFilter() string {
	// Generate a very long but valid BPF filter
	filter := "host 192.168.1.1"
	for i := 2; i < 100; i++ {
		filter += " or host 192.168.1." + fmt.Sprintf("%d", i)
	}
	return filter
}

func splitAndTrimInterfaces(interfaces string) []string {
	if interfaces == "" {
		return []string{""}
	}

	parts := strings.Split(interfaces, ",")
	result := make([]string, len(parts))
	for i, part := range parts {
		result[i] = strings.TrimSpace(part)
	}
	return result
}

// Mock implementations

type MockPcapInterface struct {
	name string
}

func (m *MockPcapInterface) Name() string {
	return m.name
}

func (m *MockPcapInterface) SetHandle() error {
	return nil // Mock success
}

func (m *MockPcapInterface) Handle() (*pcap.Handle, error) {
	return nil, errors.New("mock interface cannot provide handle") // Mock failure
}
