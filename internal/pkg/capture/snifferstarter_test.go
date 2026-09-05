package capture

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/capture/pcaptypes"
	"github.com/endorses/lippycat/internal/pkg/offline"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
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

func TestStartOfflineSnifferOrdered(t *testing.T) {
	// Test that StartOfflineSnifferOrdered function exists
	// We'll just test that the function exists and compiles
	assert.NotNil(t, StartOfflineSnifferOrdered)
}

func TestStartOfflineSnifferExtensionlessRelativeFile(t *testing.T) {
	file, err := os.CreateTemp(".", "snifferstarter-extensionless-")
	require.NoError(t, err)
	require.NoError(t, file.Close())
	name := filepath.Base(file.Name())
	t.Cleanup(func() { require.NoError(t, os.Remove(name)) })

	called := false
	StartOfflineSnifferOrdered([]string{name}, "", func(devices []pcaptypes.PcapInterface, _ string) {
		called = true
		require.Len(t, devices, 1)
		require.Equal(t, name, devices[0].Name())
	})
	require.True(t, called)
}

func TestPacketInfo(t *testing.T) {
	// Test PacketInfo struct can be created
	var pkt PacketInfo

	assert.NotNil(t, &pkt)
	// The struct should be usable even when empty
	assert.Nil(t, pkt.Packet)
}

func TestRunOfflineOrderedSortsAcrossFiles(t *testing.T) {
	base := time.Date(2026, time.August, 29, 12, 0, 0, 0, time.UTC)
	lateFile := writeTimestampedTestPCAP(t, []time.Time{base.Add(3 * time.Second), base.Add(4 * time.Second)})
	earlyFile := writeTimestampedTestPCAP(t, []time.Time{base.Add(time.Second), base.Add(2 * time.Second)})

	var devices []pcaptypes.PcapInterface
	for _, name := range []string{lateFile, earlyFile} {
		file, err := os.Open(name)
		require.NoError(t, err)
		t.Cleanup(func() { require.NoError(t, file.Close()) })
		devices = append(devices, pcaptypes.CreateOfflineInterface(file))
	}

	var got []int64
	RunOfflineOrdered(devices, "", func(ch <-chan PacketInfo) {
		for packet := range ch {
			got = append(got, packet.Packet.Metadata().Timestamp.UnixNano())
		}
	})

	require.Equal(t, []int64{
		base.Add(time.Second).UnixNano(),
		base.Add(2 * time.Second).UnixNano(),
		base.Add(3 * time.Second).UnixNano(),
		base.Add(4 * time.Second).UnixNano(),
	}, got)
}

func TestRunOfflineOrderedPreservesExactPathsForSameBasename(t *testing.T) {
	base := time.Date(2026, time.August, 29, 12, 0, 0, 0, time.UTC)
	first := writeTimestampedTestPCAP(t, []time.Time{base})
	second := writeTimestampedTestPCAP(t, []time.Time{base.Add(time.Second)})

	var devices []pcaptypes.PcapInterface
	for _, name := range []string{first, second} {
		file, err := os.Open(name)
		require.NoError(t, err)
		t.Cleanup(func() { require.NoError(t, file.Close()) })
		devices = append(devices, pcaptypes.CreateOfflineInterface(file))
	}

	var got []PacketInfo
	RunOfflineOrdered(devices, "", func(ch <-chan PacketInfo) {
		for packet := range ch {
			got = append(got, packet)
		}
	})
	require.Len(t, got, 2)
	require.Equal(t, "capture", got[0].Interface)
	require.Equal(t, "capture", got[1].Interface)
	require.Equal(t, first, got[0].SourcePath)
	require.Equal(t, second, got[1].SourcePath)
}

func TestRunOfflineOrderedContextCancelsBlockedProducer(t *testing.T) {
	input := writeTimestampedTestPCAP(t, []time.Time{time.Unix(1, 0), time.Unix(2, 0)})
	file, err := os.Open(input)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, file.Close()) })
	ctx, cancel := context.WithCancel(context.Background())
	consumerStarted := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- RunOfflineOrderedContext(ctx, []pcaptypes.PcapInterface{pcaptypes.CreateOfflineInterface(file)}, "", func(<-chan PacketInfo) {
			close(consumerStarted)
			<-ctx.Done()
		})
	}()
	<-consumerStarted
	cancel()
	select {
	case err := <-done:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(time.Second):
		t.Fatal("cancelled ordered replay left its producer blocked")
	}
}

func TestRunOfflineOrderedDoesNotPrioritizeLaterSIPPacket(t *testing.T) {
	base := time.Date(2026, time.August, 29, 12, 0, 0, 0, time.UTC)
	ordinary := writeTimestampedTestPCAPWithPayload(t, []timestampedPayload{{base.Add(time.Second), "ordinary"}})
	sip := writeTimestampedTestPCAPWithPayload(t, []timestampedPayload{{base.Add(2 * time.Second), "INVITE sip:bob@example.com SIP/2.0\r\n\r\n"}})

	var devices []pcaptypes.PcapInterface
	for _, name := range []string{ordinary, sip} {
		file, err := os.Open(name)
		require.NoError(t, err)
		t.Cleanup(func() { require.NoError(t, file.Close()) })
		devices = append(devices, pcaptypes.CreateOfflineInterface(file))
	}

	var got []int64
	RunOfflineOrdered(devices, "", func(ch <-chan PacketInfo) {
		for packet := range ch {
			got = append(got, packet.Packet.Metadata().Timestamp.UnixNano())
		}
	})

	require.Equal(t, []int64{base.Add(time.Second).UnixNano(), base.Add(2 * time.Second).UnixNano()}, got)
}

type timestampedPayload struct {
	timestamp time.Time
	payload   string
}

func writeTimestampedTestPCAP(t *testing.T, timestamps []time.Time) string {
	t.Helper()
	packets := make([]timestampedPayload, len(timestamps))
	for i, timestamp := range timestamps {
		packets[i] = timestampedPayload{timestamp: timestamp, payload: "test"}
	}
	return writeTimestampedTestPCAPWithPayload(t, packets)
}

func writeTimestampedTestPCAPWithPayload(t *testing.T, packets []timestampedPayload) string {
	t.Helper()
	name := filepath.Join(t.TempDir(), "capture")
	file, err := os.Create(name)
	require.NoError(t, err)
	writer := pcapgo.NewWriter(file)
	require.NoError(t, writer.WriteFileHeader(65535, layers.LinkTypeEthernet))

	ethernet := &layers.Ethernet{
		SrcMAC:       []byte{0, 1, 2, 3, 4, 5},
		DstMAC:       []byte{6, 7, 8, 9, 10, 11},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolUDP, SrcIP: []byte{192, 0, 2, 1}, DstIP: []byte{192, 0, 2, 2}}
	udp := &layers.UDP{SrcPort: 1000, DstPort: 2000}
	require.NoError(t, udp.SetNetworkLayerForChecksum(ip))
	for _, packet := range packets {
		buffer := gopacket.NewSerializeBuffer()
		require.NoError(t, gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, ethernet, ip, udp, gopacket.Payload(packet.payload)))
		data := buffer.Bytes()
		require.NoError(t, writer.WritePacket(gopacket.CaptureInfo{Timestamp: packet.timestamp, CaptureLength: len(data), Length: len(data)}, data))
	}
	require.NoError(t, file.Close())
	return name
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

// TestStartOfflineSnifferOrdered_ErrorHandling tests StartOfflineSnifferOrdered error paths.
func TestStartOfflineSnifferOrdered_ErrorHandling(t *testing.T) {
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

		StartOfflineSnifferOrdered([]string{testFile}, "tcp port 5060", mockStartSniffer)

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

		StartOfflineSnifferOrdered([]string{testFile, testFile2, testFile3}, "udp port 5060", mockStartSniffer)

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

		StartOfflineSnifferOrdered([]string{"/nonexistent/file.pcap"}, "tcp", mockStartSniffer)

		// Function should return early without calling startSniffer
		assert.False(t, startSnifferCalled.Load(), "startSniffer should not be called for nonexistent file")
	})

	t.Run("multiple files one not found", func(t *testing.T) {
		var startSnifferCalled atomic.Bool
		mockStartSniffer := func(devices []pcaptypes.PcapInterface, filter string) {
			startSnifferCalled.Store(true)
		}

		// Mix of existing and non-existing files
		StartOfflineSnifferOrdered([]string{testFile, "/nonexistent/file.pcap", testFile2}, "tcp", mockStartSniffer)

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

		StartOfflineSnifferOrdered([]string{testFile}, "tcp", blockingStartSniffer)

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

// TestRunOfflineOrderedProcessing tests RunOfflineOrdered with real captures.
func TestRunOfflineOrderedProcessing(t *testing.T) {
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
		processor := func(ch <-chan PacketInfo) {
			for range ch {
				processedPackets.Add(1)
			}
		}

		// Run with timeout to ensure completion
		done := make(chan struct{})
		go func() {
			RunOfflineOrdered(devices, "", processor)
			close(done)
		}()

		select {
		case <-done:
			// Completed successfully
			assert.Greater(t, processedPackets.Load(), int32(0), "Should process at least one packet")
		case <-time.After(5 * time.Second):
			t.Fatal("RunOfflineOrdered timed out")
		}
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
		processor := func(ch <-chan PacketInfo) {
			for range ch {
				processedPackets.Add(1)
			}
		}

		done := make(chan struct{})
		go func() {
			RunOfflineOrdered(devices, "", processor)
			close(done)
		}()

		select {
		case <-done:
			assert.Greater(t, processedPackets.Load(), int32(0), "Should process packets")
		case <-time.After(5 * time.Second):
			t.Fatal("RunOfflineOrdered timed out")
		}
	})
}

func offlineTestDevices(t *testing.T, names ...string) []pcaptypes.PcapInterface {
	t.Helper()
	devices := make([]pcaptypes.PcapInterface, 0, len(names))
	for _, name := range names {
		file, err := os.Open(name)
		require.NoError(t, err)
		t.Cleanup(func() { require.NoError(t, file.Close()) })
		devices = append(devices, pcaptypes.CreateOfflineInterface(file))
	}
	return devices
}

func TestRunOfflineOrderedStableTiesAndEmptySources(t *testing.T) {
	stamp := time.Unix(10, 0)
	first := writeTimestampedTestPCAPWithPayload(t, []timestampedPayload{{stamp, "first-1"}, {stamp, "first-2"}})
	empty := writeTimestampedTestPCAP(t, nil)
	second := writeTimestampedTestPCAPWithPayload(t, []timestampedPayload{{stamp, "second-1"}, {stamp, "second-2"}})
	var payloads []string
	err := RunOfflineOrderedContext(context.Background(), offlineTestDevices(t, first, empty, second), "", func(ch <-chan PacketInfo) {
		for packet := range ch {
			payloads = append(payloads, string(packet.Packet.Layer(layers.LayerTypeUDP).LayerPayload()))
		}
	})
	require.NoError(t, err)
	require.Equal(t, []string{"first-1", "first-2", "second-1", "second-2"}, payloads)
}

func TestRunOfflineOrderedPropagatesSourceErrors(t *testing.T) {
	for _, scenario := range []string{"regression", "truncated record", "invalid header", "invalid BPF", "open failure"} {
		t.Run(scenario, func(t *testing.T) {
			input := writeTimestampedTestPCAP(t, []time.Time{time.Unix(2, 0), time.Unix(3, 0)})
			filter := ""
			switch scenario {
			case "regression":
				input = writeTimestampedTestPCAP(t, []time.Time{time.Unix(2, 0), time.Unix(1, 0)})
			case "truncated record":
				info, err := os.Stat(input)
				require.NoError(t, err)
				require.NoError(t, os.Truncate(input, info.Size()-1))
			case "invalid header":
				require.NoError(t, os.WriteFile(input, []byte("not a capture"), 0600))
			case "invalid BPF":
				filter = "udp and ("
			}
			devices := offlineTestDevices(t, input)
			if scenario == "open failure" {
				require.NoError(t, os.Remove(input))
			}
			err := RunOfflineOrderedContext(context.Background(), devices, filter, func(ch <-chan PacketInfo) {
				for range ch {
				}
			})
			require.Error(t, err)
			require.Contains(t, err.Error(), input, "errors must identify the exact source")
			if scenario == "regression" {
				require.Contains(t, strings.ToLower(err.Error()), "regress")
				var regression *offline.TimestampRegressionError
				require.ErrorAs(t, err, &regression)
				require.Equal(t, uint64(1), regression.Source.Sequence)
				require.Equal(t, uint32(0), regression.Source.ArgumentIndex)
			}
		})
	}
}

func TestRunOfflineOrderedStreamConsumerFailure(t *testing.T) {
	input := writeTimestampedTestPCAP(t, []time.Time{time.Unix(1, 0), time.Unix(2, 0)})
	devices := offlineTestDevices(t, input)
	failure := errors.New("downstream storage full")
	done := make(chan error, 1)
	go func() {
		done <- RunOfflineOrderedStream(context.Background(), devices, "", func(context.Context, <-chan PacketInfo) error {
			return failure
		})
	}()
	select {
	case err := <-done:
		require.ErrorIs(t, err, failure)
	case <-time.After(2 * time.Second):
		t.Fatal("consumer failure did not unblock the producer")
	}
}

func TestRunOfflineOrderedStreamConsumerEarlyReturn(t *testing.T) {
	input := writeTimestampedTestPCAP(t, []time.Time{time.Unix(1, 0), time.Unix(2, 0)})
	devices := offlineTestDevices(t, input)
	done := make(chan error, 1)
	go func() {
		done <- RunOfflineOrderedStream(context.Background(), devices, "", func(context.Context, <-chan PacketInfo) error {
			return nil
		})
	}()
	select {
	case err := <-done:
		require.Error(t, err, "early return must not report a complete capture")
	case <-time.After(2 * time.Second):
		t.Fatal("consumer early return did not unblock the producer")
	}
}

func TestRunOfflineOrderedMixedCaptureFormats(t *testing.T) {
	first := writeTimestampedTestPCAP(t, []time.Time{time.Unix(1, 0), time.Unix(3, 0)})
	original := writeTimestampedTestPCAP(t, []time.Time{time.Unix(2, 0), time.Unix(4, 0)})
	in, err := os.Open(original)
	require.NoError(t, err)
	reader, err := pcapgo.NewReader(in)
	require.NoError(t, err)
	name := filepath.Join(t.TempDir(), "capture.pcapng")
	out, err := os.Create(name)
	require.NoError(t, err)
	writer, err := pcapgo.NewNgWriter(out, layers.LinkTypeEthernet)
	require.NoError(t, err)
	for i := 0; i < 2; i++ {
		data, ci, err := reader.ReadPacketData()
		require.NoError(t, err)
		require.NoError(t, writer.WritePacket(ci, data))
	}
	require.NoError(t, writer.Flush())
	require.NoError(t, out.Close())
	require.NoError(t, in.Close())
	var got []PacketInfo
	err = RunOfflineOrderedContext(context.Background(), offlineTestDevices(t, first, name), "udp dst port 2000", func(ch <-chan PacketInfo) {
		for packet := range ch {
			got = append(got, packet)
		}
	})
	require.NoError(t, err)
	require.Len(t, got, 4)
	for i, packet := range got {
		require.Equal(t, int64(i+1), packet.Packet.Metadata().Timestamp.Unix())
		require.Equal(t, "test", string(packet.Packet.Layer(layers.LayerTypeUDP).LayerPayload()), "retained packet bytes must survive subsequent reads")
	}
	require.Equal(t, name, got[1].SourcePath)
}

func TestRunOfflineOrderedStreamsBeforeReadingLaterCorruption(t *testing.T) {
	input := writeTimestampedTestPCAP(t, []time.Time{time.Unix(1, 0), time.Unix(2, 0)})
	info, err := os.Stat(input)
	require.NoError(t, err)
	require.NoError(t, os.Truncate(input, info.Size()-1))
	var got []PacketInfo
	err = RunOfflineOrderedContext(context.Background(), offlineTestDevices(t, input), "", func(ch <-chan PacketInfo) {
		for packet := range ch {
			got = append(got, packet)
		}
	})
	require.Error(t, err)
	require.Len(t, got, 1, "the first packet must be delivered before reading the malformed second record")
	require.Equal(t, int64(1), got[0].Packet.Metadata().Timestamp.Unix())
}

func TestRunOfflineOrderedSourceLimitBeforeOpening(t *testing.T) {
	devices := make([]pcaptypes.PcapInterface, MaxOfflineSources+1)
	for i := range devices {
		devices[i] = &mockPcapInterface{name: "/nonexistent/never-open.pcap"}
	}
	called := false
	err := RunOfflineOrderedContext(context.Background(), devices, "", func(<-chan PacketInfo) { called = true })
	require.Error(t, err)
	require.Contains(t, err.Error(), "at most")
	require.NotContains(t, err.Error(), "no such file")
	require.False(t, called)
}

func TestRunOfflineOrderedCancellationDuringConsumerDrain(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	err := RunOfflineOrderedStream(ctx, nil, "", func(ctx context.Context, ch <-chan PacketInfo) error {
		for range ch {
		}
		cancel()
		return nil
	})
	require.ErrorIs(t, err, context.Canceled)
}
