package capture

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/capture/pcaptypes"
	"github.com/google/gopacket/pcap"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
	// Create test PCAP files
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.pcap")
	testFile2 := filepath.Join(tmpDir, "test2.pcap")
	testFile3 := filepath.Join(tmpDir, "test3.pcap")

	for _, f := range []string{testFile, testFile2, testFile3} {
		file, err := os.Create(f)
		require.NoError(t, err)
		file.Close()
	}

	t.Run("success", func(t *testing.T) {
		var capturedDevices []pcaptypes.PcapInterface
		var capturedFilter string
		var startSnifferCalled atomic.Bool

		mockStartSniffer := func(devices []pcaptypes.PcapInterface, filter string) {
			startSnifferCalled.Store(true)
			capturedDevices = devices
			capturedFilter = filter
		}

		StartOfflineSniffer([]string{testFile}, "tcp port 5060", mockStartSniffer)

		assert.True(t, startSnifferCalled.Load(), "startSniffer should be called")
		assert.Equal(t, 1, len(capturedDevices), "Should create one offline device")
		assert.Contains(t, capturedDevices[0].Name(), "test.pcap", "Device name should contain filename")
		assert.Equal(t, "tcp port 5060", capturedFilter, "Filter should be passed through")
	})

	t.Run("multiple files success", func(t *testing.T) {
		var capturedDevices []pcaptypes.PcapInterface
		var capturedFilter string
		var startSnifferCalled atomic.Bool

		mockStartSniffer := func(devices []pcaptypes.PcapInterface, filter string) {
			startSnifferCalled.Store(true)
			capturedDevices = devices
			capturedFilter = filter
		}

		StartOfflineSniffer([]string{testFile, testFile2, testFile3}, "udp port 5060", mockStartSniffer)

		assert.True(t, startSnifferCalled.Load(), "startSniffer should be called")
		assert.Equal(t, 3, len(capturedDevices), "Should create three offline devices")
		assert.Contains(t, capturedDevices[0].Name(), "test.pcap", "First device name should contain filename")
		assert.Contains(t, capturedDevices[1].Name(), "test2.pcap", "Second device name should contain filename")
		assert.Contains(t, capturedDevices[2].Name(), "test3.pcap", "Third device name should contain filename")
		assert.Equal(t, "udp port 5060", capturedFilter, "Filter should be passed through")
	})

	t.Run("file not found", func(t *testing.T) {
		var startSnifferCalled atomic.Bool
		mockStartSniffer := func(devices []pcaptypes.PcapInterface, filter string) {
			startSnifferCalled.Store(true)
		}

		StartOfflineSniffer([]string{"/nonexistent/file.pcap"}, "tcp", mockStartSniffer)

		// Function should return early without calling startSniffer
		assert.False(t, startSnifferCalled.Load(), "startSniffer should not be called for nonexistent file")
	})

	t.Run("multiple files one not found", func(t *testing.T) {
		var startSnifferCalled atomic.Bool
		mockStartSniffer := func(devices []pcaptypes.PcapInterface, filter string) {
			startSnifferCalled.Store(true)
		}

		// Mix of existing and non-existing files
		StartOfflineSniffer([]string{testFile, "/nonexistent/file.pcap", testFile2}, "tcp", mockStartSniffer)

		// Function should return early without calling startSniffer when any file is missing
		assert.False(t, startSnifferCalled.Load(), "startSniffer should not be called when one file is missing")
	})

	t.Run("timeout handling", func(t *testing.T) {
		var startSnifferCalled atomic.Bool
		blockingStartSniffer := func(devices []pcaptypes.PcapInterface, filter string) {
			startSnifferCalled.Store(true)
			// Block briefly to test goroutine execution
			time.Sleep(10 * time.Millisecond)
		}

		StartOfflineSniffer([]string{testFile}, "tcp", blockingStartSniffer)

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
		processor := func(ch <-chan PacketInfo, asm *TCPAssembler) {
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
		processor := func(ch <-chan PacketInfo, asm *TCPAssembler) {
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
		processor := func(ch <-chan PacketInfo, asm *TCPAssembler) {
			for range ch {
				processedPackets.Add(1)
			}
		}

		// Create TCP assembler
		streamFactory := &MockStreamFactory{}
		assembler := NewTCPAssembler(streamFactory)

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
