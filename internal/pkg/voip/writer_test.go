//go:build cli || all

package voip

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCloseWriters(t *testing.T) {
	originalSipFile := sipFile
	originalRtpFile := rtpFile
	defer func() {
		sipFile = originalSipFile
		rtpFile = originalRtpFile
	}()

	tests := []struct {
		name        string
		setupFiles  func(*testing.T) (*os.File, *os.File)
		expectError bool
	}{
		{
			name: "Close valid files",
			setupFiles: func(t *testing.T) (*os.File, *os.File) {
				tmpDir := t.TempDir()
				sipF, err := os.Create(filepath.Join(tmpDir, "test_sip.pcap"))
				require.NoError(t, err)
				rtpF, err := os.Create(filepath.Join(tmpDir, "test_rtp.pcap"))
				require.NoError(t, err)
				return sipF, rtpF
			},
			expectError: false,
		},
		{
			name: "Close nil files",
			setupFiles: func(t *testing.T) (*os.File, *os.File) {
				return nil, nil
			},
			expectError: false,
		},
		{
			name: "Close already closed files",
			setupFiles: func(t *testing.T) (*os.File, *os.File) {
				tmpDir := t.TempDir()
				sipF, err := os.Create(filepath.Join(tmpDir, "test_sip2.pcap"))
				require.NoError(t, err)
				rtpF, err := os.Create(filepath.Join(tmpDir, "test_rtp2.pcap"))
				require.NoError(t, err)
				// Close them first
				sipF.Close()
				rtpF.Close()
				return sipF, rtpF
			},
			expectError: true, // Closing already closed files will log errors
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sipFile, rtpFile = tt.setupFiles(t)

			// This should not panic
			assert.NotPanics(t, func() {
				CloseWriters()
			})

			// Files should be set to nil after closing
			assert.Nil(t, sipFile)
			assert.Nil(t, rtpFile)
		})
	}
}

func TestWriteSIP(t *testing.T) {
	// Get tracker for fresh state
	tracker := getTracker()

	// Reset shutdown flag to allow writes (other tests may have shut down the tracker)
	tracker.shuttingDown.Store(0)

	tracker.mu.Lock()
	originalCallMap := make(map[string]*CallInfo)
	for k, v := range tracker.callMap {
		originalCallMap[k] = v
	}
	tracker.callMap = make(map[string]*CallInfo)
	tracker.mu.Unlock()

	defer func() {
		tracker.mu.Lock()
		tracker.callMap = originalCallMap
		tracker.mu.Unlock()
	}()

	tests := []struct {
		name        string
		callID      string
		setupCall   func(*testing.T, string) *CallInfo
		shouldWrite bool
	}{
		{
			name:   "Write SIP packet for existing call with writer",
			callID: "test-call-sip-1",
			setupCall: func(t *testing.T, callID string) *CallInfo {
				return createCallWithSIPWriter(t, callID)
			},
			shouldWrite: true,
		},
		{
			name:   "Write SIP packet for non-existent call",
			callID: "non-existent-call",
			setupCall: func(t *testing.T, callID string) *CallInfo {
				return nil // Don't create call
			},
			shouldWrite: false,
		},
		{
			name:   "Write SIP packet for call without SIP writer",
			callID: "test-call-no-writer",
			setupCall: func(t *testing.T, callID string) *CallInfo {
				call := &CallInfo{
					CallID:      callID,
					State:       "active",
					Created:     time.Now(),
					LastUpdated: time.Now(),
					LinkType:    layers.LinkTypeEthernet,
					SIPWriter:   nil, // No writer
				}
				return call
			},
			shouldWrite: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var call *CallInfo
			if tt.setupCall != nil {
				call = tt.setupCall(t, tt.callID)
				if call != nil {
					tracker.mu.Lock()
					tracker.callMap[tt.callID] = call
					tracker.mu.Unlock()
				}
			}

			packet := createMockSIPPacket()
			originalTime := time.Time{}
			if call != nil {
				// Read LastUpdated with proper locking to avoid data race
				tracker.mu.Lock()
				originalTime = call.LastUpdated
				tracker.mu.Unlock()
			}

			// Ensure we have a clear time boundary
			time.Sleep(2 * time.Millisecond)

			// This should not panic
			// Call writeSIPSync directly to bypass async writer and ensure deterministic test behavior
			assert.NotPanics(t, func() {
				writeSIPSync(tt.callID, packet)
			})

			if tt.shouldWrite && call != nil {
				// LastUpdated should be modified (synchronous write completes before returning)
				tracker.mu.Lock()
				updatedCall := tracker.callMap[tt.callID]
				tracker.mu.Unlock()

				assert.True(t, updatedCall.LastUpdated.After(originalTime),
					"LastUpdated should be updated after successful write")
			}
		})
	}
}

func TestWriteRTP(t *testing.T) {
	// Get tracker for fresh state
	tracker := getTracker()

	// Reset shutdown flag to allow writes (other tests may have shut down the tracker)
	tracker.shuttingDown.Store(0)

	tracker.mu.Lock()
	originalCallMap := make(map[string]*CallInfo)
	for k, v := range tracker.callMap {
		originalCallMap[k] = v
	}
	tracker.callMap = make(map[string]*CallInfo)
	tracker.mu.Unlock()

	defer func() {
		tracker.mu.Lock()
		tracker.callMap = originalCallMap
		tracker.mu.Unlock()
	}()

	tests := []struct {
		name        string
		callID      string
		setupCall   func(*testing.T, string) *CallInfo
		shouldWrite bool
	}{
		{
			name:   "Write RTP packet for existing call with writer",
			callID: "test-call-rtp-1",
			setupCall: func(t *testing.T, callID string) *CallInfo {
				return createCallWithRTPWriter(t, callID)
			},
			shouldWrite: true,
		},
		{
			name:   "Write RTP packet for non-existent call",
			callID: "non-existent-call-rtp",
			setupCall: func(t *testing.T, callID string) *CallInfo {
				return nil // Don't create call
			},
			shouldWrite: false,
		},
		{
			name:   "Write RTP packet for call without RTP writer",
			callID: "test-call-no-rtp-writer",
			setupCall: func(t *testing.T, callID string) *CallInfo {
				call := &CallInfo{
					CallID:      callID,
					State:       "active",
					Created:     time.Now(),
					LastUpdated: time.Now(),
					LinkType:    layers.LinkTypeEthernet,
					RTPWriter:   nil, // No writer
				}
				return call
			},
			shouldWrite: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var call *CallInfo
			if tt.setupCall != nil {
				call = tt.setupCall(t, tt.callID)
				if call != nil {
					tracker.mu.Lock()
					tracker.callMap[tt.callID] = call
					tracker.mu.Unlock()
				}
			}

			packet := createMockRTPPacket()
			originalTime := time.Time{}
			if call != nil {
				// Read LastUpdated with proper locking to avoid data race
				tracker.mu.Lock()
				originalTime = call.LastUpdated
				tracker.mu.Unlock()
			}

			// Ensure we have a clear time boundary
			time.Sleep(2 * time.Millisecond)

			// This should not panic
			// Call writeRTPSync directly to bypass async writer and ensure deterministic test behavior
			assert.NotPanics(t, func() {
				writeRTPSync(tt.callID, packet)
			})

			if tt.shouldWrite && call != nil {
				// LastUpdated should be modified (synchronous write completes before returning)
				tracker.mu.Lock()
				updatedCall := tracker.callMap[tt.callID]
				tracker.mu.Unlock()

				assert.True(t, updatedCall.LastUpdated.After(originalTime),
					"LastUpdated should be updated after successful write")
			}
		})
	}
}

func TestWritersConcurrency(t *testing.T) {
	// Test concurrent access to WriteSIP and WriteRTP
	tracker := getTracker()
	tracker.mu.Lock()
	originalCallMap := make(map[string]*CallInfo)
	for k, v := range tracker.callMap {
		originalCallMap[k] = v
	}
	tracker.callMap = make(map[string]*CallInfo)
	tracker.mu.Unlock()

	defer func() {
		tracker.mu.Lock()
		tracker.callMap = originalCallMap
		tracker.mu.Unlock()
	}()

	// Setup multiple calls
	calls := []string{"call1", "call2", "call3"}
	for _, callID := range calls {
		call := createCallWithBothWriters(t, callID)
		tracker.mu.Lock()
		tracker.callMap[callID] = call
		tracker.mu.Unlock()
	}

	var wg sync.WaitGroup
	const numGoroutines = 10
	const operationsPerGoroutine = 50

	// Start goroutines writing SIP packets
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < operationsPerGoroutine; j++ {
				callID := calls[j%len(calls)]
				packet := createMockSIPPacket()
				WriteSIP(callID, packet)
			}
		}(i)
	}

	// Start goroutines writing RTP packets
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < operationsPerGoroutine; j++ {
				callID := calls[j%len(calls)]
				packet := createMockRTPPacket()
				WriteRTP(callID, packet)
			}
		}(i)
	}

	// This should not deadlock or panic
	assert.NotPanics(t, func() {
		wg.Wait()
	})

	// Verify all calls still exist and have updated timestamps
	tracker.mu.Lock()
	for _, callID := range calls {
		call, exists := tracker.callMap[callID]
		assert.True(t, exists, "Call should still exist after concurrent operations")
		assert.True(t, call.LastUpdated.After(call.Created), "LastUpdated should be after Created")
	}
	tracker.mu.Unlock()
}

// Helper functions to create mock packets
func createMockSIPPacket() gopacket.Packet {
	// Create a basic packet with SIP-like data
	eth := &layers.Ethernet{
		SrcMAC:       []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05},
		DstMAC:       []byte{0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		SrcIP:    []byte{192, 168, 1, 100},
		DstIP:    []byte{192, 168, 1, 200},
		Protocol: layers.IPProtocolUDP,
	}
	udp := &layers.UDP{
		SrcPort: 5060,
		DstPort: 5060,
	}
	udp.SetNetworkLayerForChecksum(ip)

	sipData := []byte("INVITE sip:user@example.com SIP/2.0\r\nCall-ID: test-call\r\n")

	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	gopacket.SerializeLayers(buffer, options, eth, ip, udp, gopacket.Payload(sipData))

	packet := gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
	packet.Metadata().Timestamp = time.Now()
	packet.Metadata().CaptureInfo.CaptureLength = len(buffer.Bytes())
	packet.Metadata().CaptureInfo.Length = len(buffer.Bytes())
	return packet
}

func createMockRTPPacket() gopacket.Packet {
	// Create a basic RTP packet
	eth := &layers.Ethernet{
		SrcMAC:       []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05},
		DstMAC:       []byte{0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		SrcIP:    []byte{192, 168, 1, 100},
		DstIP:    []byte{192, 168, 1, 200},
		Protocol: layers.IPProtocolUDP,
	}
	udp := &layers.UDP{
		SrcPort: 5004,
		DstPort: 5004,
	}
	udp.SetNetworkLayerForChecksum(ip)

	// Mock RTP payload
	rtpData := []byte{0x80, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	gopacket.SerializeLayers(buffer, options, eth, ip, udp, gopacket.Payload(rtpData))

	packet := gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
	packet.Metadata().Timestamp = time.Now()
	packet.Metadata().CaptureInfo.CaptureLength = len(buffer.Bytes())
	packet.Metadata().CaptureInfo.Length = len(buffer.Bytes())
	return packet
}

// Helper function to create a call with SIP writer
func createCallWithSIPWriter(t *testing.T, callID string) *CallInfo {
	tmpDir := t.TempDir()
	sipFile, err := os.Create(filepath.Join(tmpDir, callID+"_sip.pcap"))
	require.NoError(t, err)

	call := &CallInfo{
		CallID:      callID,
		State:       "active",
		Created:     time.Now(),
		LastUpdated: time.Now(),
		LinkType:    layers.LinkTypeEthernet,
		sipFile:     sipFile,
	}
	call.SIPWriter = pcapgo.NewWriter(sipFile)
	call.SIPWriter.WriteFileHeader(65536, layers.LinkTypeEthernet)

	return call
}

// Helper function to create a call with RTP writer
func createCallWithRTPWriter(t *testing.T, callID string) *CallInfo {
	tmpDir := t.TempDir()
	rtpFile, err := os.Create(filepath.Join(tmpDir, callID+"_rtp.pcap"))
	require.NoError(t, err)

	call := &CallInfo{
		CallID:      callID,
		State:       "active",
		Created:     time.Now(),
		LastUpdated: time.Now(),
		LinkType:    layers.LinkTypeEthernet,
		rtpFile:     rtpFile,
	}
	call.RTPWriter = pcapgo.NewWriter(rtpFile)
	call.RTPWriter.WriteFileHeader(65536, layers.LinkTypeEthernet)

	return call
}

// Helper function to create a call with both SIP and RTP writers
func createCallWithBothWriters(t *testing.T, callID string) *CallInfo {
	tmpDir := t.TempDir()
	sipFile, err := os.Create(filepath.Join(tmpDir, callID+"_sip.pcap"))
	require.NoError(t, err)
	rtpFile, err := os.Create(filepath.Join(tmpDir, callID+"_rtp.pcap"))
	require.NoError(t, err)

	call := &CallInfo{
		CallID:      callID,
		State:       "active",
		Created:     time.Now(),
		LastUpdated: time.Now(),
		LinkType:    layers.LinkTypeEthernet,
		sipFile:     sipFile,
		rtpFile:     rtpFile,
	}
	call.SIPWriter = pcapgo.NewWriter(sipFile)
	call.SIPWriter.WriteFileHeader(65536, layers.LinkTypeEthernet)
	call.RTPWriter = pcapgo.NewWriter(rtpFile)
	call.RTPWriter.WriteFileHeader(65536, layers.LinkTypeEthernet)

	return call
}
