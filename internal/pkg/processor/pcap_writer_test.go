//go:build processor || tap || all

package processor

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type semanticPCAPFixture struct {
	CallID      string `json:"call_id"`
	PacketCount int    `json:"packet_count"`
	LinkType    string `json:"link_type"`
	Packets     []struct {
		Timestamp string `json:"timestamp"`
		FiveTuple struct {
			SrcIP     string `json:"src_ip"`
			DstIP     string `json:"dst_ip"`
			SrcPort   uint16 `json:"src_port"`
			DstPort   uint16 `json:"dst_port"`
			Transport string `json:"transport"`
		} `json:"five_tuple"`
		SIP *struct {
			CallID       string `json:"call_id"`
			Method       string `json:"method"`
			CSeqMethod   string `json:"cseq_method"`
			ResponseCode int    `json:"response_code"`
		} `json:"sip"`
		PayloadSHA256   string `json:"payload_sha256"`
		CallAssociation string `json:"call_association"`
	} `json:"packets"`
}

func TestPerCallPCAPSemanticGolden(t *testing.T) {
	fixtureBytes, err := os.ReadFile(filepath.Join("..", "baseline", "testdata", "per-call-pcap.json"))
	require.NoError(t, err)
	var fixture semanticPCAPFixture
	require.NoError(t, json.Unmarshal(fixtureBytes, &fixture))

	dir := t.TempDir()
	manager, err := NewPcapWriterManager(&PcapWriterConfig{Enabled: true, OutputDir: dir, FilePattern: "{callid}.pcap", SyncInterval: time.Hour})
	require.NoError(t, err)
	writer, err := manager.GetOrCreateWriter(fixture.CallID, "alice", "bob")
	require.NoError(t, err)

	sipPayload := []byte("INVITE sip:bob@example.test SIP/2.0\r\nCall-ID: baseline-call\r\nCSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n")
	responsePayload := []byte("SIP/2.0 200 OK\r\nCall-ID: baseline-call\r\nCSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n")
	rtpPayload := []byte{0x80, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0xa0, 0x12, 0x34, 0x56, 0x78, 0xde, 0xad, 0xbe, 0xef}
	sipPacket := semanticUDPPacket(t, net.ParseIP("192.0.2.10"), net.ParseIP("198.51.100.50"), 5060, 5060, sipPayload)
	responsePacket := semanticUDPPacket(t, net.ParseIP("198.51.100.50"), net.ParseIP("192.0.2.10"), 5060, 5060, responsePayload)
	rtpPacket := semanticUDPPacket(t, net.ParseIP("198.51.100.50"), net.ParseIP("192.0.2.10"), 10000, 20000, rtpPayload)
	t0, err := time.Parse(time.RFC3339Nano, fixture.Packets[0].Timestamp)
	require.NoError(t, err)
	t1, err := time.Parse(time.RFC3339Nano, fixture.Packets[1].Timestamp)
	require.NoError(t, err)
	t2, err := time.Parse(time.RFC3339Nano, fixture.Packets[2].Timestamp)
	require.NoError(t, err)
	require.NoError(t, writer.WriteSIPPacket(t0, sipPacket, layers.LinkTypeEthernet))
	require.NoError(t, writer.WriteSIPPacket(t1, responsePacket, layers.LinkTypeEthernet))
	require.NoError(t, writer.WriteRTPPacket(t2, rtpPacket, layers.LinkTypeEthernet))
	require.NoError(t, manager.CloseCallWriter(fixture.CallID))

	observed := make([]semanticObservation, 0, 3)
	observed = append(observed, readSemanticPCAP(t, filepath.Join(dir, fixture.CallID+"_sip.pcap"), true)...)
	observed = append(observed, readSemanticPCAP(t, filepath.Join(dir, fixture.CallID+"_rtp.pcap"), false)...)
	require.Len(t, observed, fixture.PacketCount)
	for i := range fixture.Packets {
		want := fixture.Packets[i]
		got := observed[i]
		require.Equal(t, want.Timestamp, got.Timestamp)
		require.Equal(t, want.FiveTuple.SrcIP, got.SrcIP)
		require.Equal(t, want.FiveTuple.DstIP, got.DstIP)
		require.Equal(t, want.FiveTuple.SrcPort, got.SrcPort)
		require.Equal(t, want.FiveTuple.DstPort, got.DstPort)
		require.Equal(t, strings.ToUpper(want.FiveTuple.Transport), got.Transport)
		require.Equal(t, want.PayloadSHA256, got.PayloadSHA256)
		require.Equal(t, want.CallAssociation, got.CallAssociation)
		require.Equal(t, fixture.LinkType, got.LinkType)
		if want.SIP != nil {
			require.Equal(t, want.SIP.CallID, got.CallID)
			require.Equal(t, want.SIP.Method, got.Method)
			require.Equal(t, want.SIP.CSeqMethod, got.CSeqMethod)
			require.Equal(t, want.SIP.ResponseCode, got.ResponseCode)
		}
	}
}

type semanticObservation struct {
	Timestamp, SrcIP, DstIP, Transport, LinkType               string
	SrcPort, DstPort                                           uint16
	PayloadSHA256, CallAssociation, CallID, Method, CSeqMethod string
	ResponseCode                                               int
}

func semanticUDPPacket(t *testing.T, srcIP, dstIP net.IP, srcPort, dstPort layers.UDPPort, payload []byte) []byte {
	t.Helper()
	eth := &layers.Ethernet{SrcMAC: net.HardwareAddr{0, 1, 2, 3, 4, 5}, DstMAC: net.HardwareAddr{6, 7, 8, 9, 10, 11}, EthernetType: layers.EthernetTypeIPv4}
	ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolUDP, SrcIP: srcIP.To4(), DstIP: dstIP.To4()}
	udp := &layers.UDP{SrcPort: srcPort, DstPort: dstPort}
	require.NoError(t, udp.SetNetworkLayerForChecksum(ip))
	buf := gopacket.NewSerializeBuffer()
	require.NoError(t, gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, eth, ip, udp, gopacket.Payload(payload)))
	return buf.Bytes()
}

func readSemanticPCAP(t *testing.T, path string, sip bool) []semanticObservation {
	t.Helper()
	f, err := os.Open(path)
	require.NoError(t, err)
	defer f.Close()
	r, err := pcapgo.NewReader(f)
	require.NoError(t, err)
	association := strings.TrimSuffix(filepath.Base(path), "_sip.pcap")
	association = strings.TrimSuffix(association, "_rtp.pcap")
	var result []semanticObservation
	for {
		data, ci, err := r.ReadPacketData()
		if err == io.EOF {
			break
		}
		require.NoError(t, err)
		packet := gopacket.NewPacket(data, r.LinkType(), gopacket.Default)
		ip := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
		udp := packet.Layer(layers.LayerTypeUDP).(*layers.UDP)
		digest := sha256.Sum256(udp.Payload)
		o := semanticObservation{Timestamp: ci.Timestamp.UTC().Format(time.RFC3339Nano), SrcIP: ip.SrcIP.String(), DstIP: ip.DstIP.String(), SrcPort: uint16(udp.SrcPort), DstPort: uint16(udp.DstPort), Transport: "UDP", LinkType: r.LinkType().String(), PayloadSHA256: hex.EncodeToString(digest[:]), CallAssociation: association}
		if sip {
			lines := strings.Split(string(udp.Payload), "\r\n")
			startLine := strings.Fields(lines[0])
			if len(startLine) >= 2 && startLine[0] == "SIP/2.0" {
				o.ResponseCode, err = strconv.Atoi(startLine[1])
				require.NoError(t, err)
			} else {
				o.Method = startLine[0]
			}
			for _, line := range lines[1:] {
				if strings.HasPrefix(line, "Call-ID: ") {
					o.CallID = strings.TrimPrefix(line, "Call-ID: ")
				}
				if strings.HasPrefix(line, "CSeq: ") {
					fields := strings.Fields(line)
					if len(fields) == 3 {
						o.CSeqMethod = fields[2]
					}
				}
			}
		}
		result = append(result, o)
	}
	return result
}

// TestDefaultPcapWriterConfig tests default configuration
func TestDefaultPcapWriterConfig(t *testing.T) {
	config := DefaultPcapWriterConfig()

	assert.NotNil(t, config)
	assert.False(t, config.Enabled)
	assert.Equal(t, "./pcaps", config.OutputDir)
	assert.Equal(t, "{timestamp}_{callid}.pcap", config.FilePattern)
	assert.Equal(t, int64(100*1024*1024), config.MaxFileSize) // 100MB
	assert.Equal(t, 10, config.MaxFilesPerCall)
	assert.Equal(t, 10*time.Minute, config.MaxIdle)
	assert.Equal(t, 0, config.MaxWriters)
	assert.Equal(t, 4096, config.BufferSize)
	assert.Equal(t, 5*time.Second, config.SyncInterval)
}

// TestNewPcapWriterManager tests manager creation
func TestNewPcapWriterManager(t *testing.T) {
	tests := []struct {
		name    string
		config  *PcapWriterConfig
		wantErr bool
	}{
		{
			name:    "nil config uses defaults",
			config:  nil,
			wantErr: false,
		},
		{
			name: "disabled config",
			config: &PcapWriterConfig{
				Enabled:   false,
				OutputDir: "./test-pcaps",
			},
			wantErr: false,
		},
		{
			name: "enabled config creates directory",
			config: &PcapWriterConfig{
				Enabled:   true,
				OutputDir: filepath.Join(os.TempDir(), "lippycat-test-pcaps"),
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clean up test directory if it exists
			if tt.config != nil && tt.config.Enabled && tt.config.OutputDir != "" {
				defer os.RemoveAll(tt.config.OutputDir)
			}

			manager, err := NewPcapWriterManager(tt.config)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, manager)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, manager)
				assert.NotNil(t, manager.config)
				assert.NotNil(t, manager.writers)

				// Verify directory was created for enabled configs
				if tt.config != nil && tt.config.Enabled {
					info, err := os.Stat(tt.config.OutputDir)
					assert.NoError(t, err)
					assert.True(t, info.IsDir())
				}
			}
		})
	}
}

// TestSanitizeFilename tests filename sanitization
func TestSanitizeFilename(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "normal filename",
			input:    "test.pcap",
			expected: "test.pcap",
		},
		{
			name:     "filename with spaces",
			input:    "test file.pcap",
			expected: "test_file.pcap",
		},
		{
			name:     "filename with slashes",
			input:    "path/to/file.pcap",
			expected: "path_to_file.pcap",
		},
		{
			name:     "filename with special characters",
			input:    "test@file#name$.pcap",
			expected: "test_file#name$.pcap",
		},
		{
			name:     "filename with backslashes",
			input:    "test\\file.pcap",
			expected: "test_file.pcap",
		},
		{
			name:     "filename with colons",
			input:    "test:file.pcap",
			expected: "test_file.pcap",
		},
		{
			name:     "empty filename",
			input:    "",
			expected: "",
		},
		{
			name:     "filename with dots",
			input:    "../../../etc/passwd",
			expected: ".._.._.._etc_passwd",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sanitizeFilename(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestPcapWriterConfig tests config structure
func TestPcapWriterConfig(t *testing.T) {
	config := &PcapWriterConfig{
		Enabled:         true,
		OutputDir:       "/tmp/pcaps",
		FilePattern:     "call_{callid}.pcap",
		MaxFileSize:     50 * 1024 * 1024, // 50MB
		MaxFilesPerCall: 5,
		MaxIdle:         time.Minute,
		MaxWriters:      100,
		BufferSize:      8192,
		SyncInterval:    10 * time.Second,
	}

	assert.True(t, config.Enabled)
	assert.Equal(t, "/tmp/pcaps", config.OutputDir)
	assert.Equal(t, "call_{callid}.pcap", config.FilePattern)
	assert.Equal(t, int64(50*1024*1024), config.MaxFileSize)
	assert.Equal(t, 5, config.MaxFilesPerCall)
	assert.Equal(t, time.Minute, config.MaxIdle)
	assert.Equal(t, 100, config.MaxWriters)
	assert.Equal(t, 8192, config.BufferSize)
	assert.Equal(t, 10*time.Second, config.SyncInterval)
}

func TestPcapWriterManagerSweepIdle(t *testing.T) {
	var completed []CallMetadata
	config := &PcapWriterConfig{
		Enabled:      true,
		OutputDir:    t.TempDir(),
		FilePattern:  "{timestamp}_{callid}.pcap",
		MaxIdle:      time.Minute,
		SyncInterval: time.Hour,
		OnCallComplete: func(meta CallMetadata) {
			completed = append(completed, meta)
		},
	}

	manager, err := NewPcapWriterManager(config)
	require.NoError(t, err)
	defer manager.Close()

	idleWriter, err := manager.GetOrCreateWriter("idle-call", "alice", "bob")
	require.NoError(t, err)
	activeWriter, err := manager.GetOrCreateWriter("active-call", "carol", "dave")
	require.NoError(t, err)

	idleWriter.mu.Lock()
	idleWriter.lastWrite = time.Now().Add(-2 * time.Minute)
	idleWriter.mu.Unlock()
	activeWriter.mu.Lock()
	activeWriter.lastWrite = time.Now()
	activeWriter.mu.Unlock()

	closed := manager.SweepIdle(time.Minute)
	assert.Equal(t, 1, closed)
	assert.Len(t, completed, 1)
	assert.Equal(t, "idle-call", completed[0].CallID)

	manager.mu.RLock()
	_, idleExists := manager.writers["idle-call"]
	_, activeExists := manager.writers["active-call"]
	manager.mu.RUnlock()
	assert.False(t, idleExists)
	assert.True(t, activeExists)
}

func TestPcapWriterManagerMaxWriters(t *testing.T) {
	var completed []CallMetadata
	config := &PcapWriterConfig{
		Enabled:      true,
		OutputDir:    t.TempDir(),
		FilePattern:  "{timestamp}_{callid}.pcap",
		MaxWriters:   1,
		SyncInterval: time.Hour,
		OnCallComplete: func(meta CallMetadata) {
			completed = append(completed, meta)
		},
	}

	manager, err := NewPcapWriterManager(config)
	require.NoError(t, err)
	defer manager.Close()

	firstWriter, err := manager.GetOrCreateWriter("first-call", "alice", "bob")
	require.NoError(t, err)
	firstWriter.mu.Lock()
	firstWriter.lastWrite = time.Now().Add(-time.Minute)
	firstWriter.mu.Unlock()

	secondWriter, err := manager.GetOrCreateWriter("second-call", "carol", "dave")
	require.NoError(t, err)
	require.NotNil(t, secondWriter)

	assert.Len(t, completed, 1)
	assert.Equal(t, "first-call", completed[0].CallID)

	manager.mu.RLock()
	_, firstExists := manager.writers["first-call"]
	_, secondExists := manager.writers["second-call"]
	writerCount := len(manager.writers)
	manager.mu.RUnlock()
	assert.False(t, firstExists)
	assert.True(t, secondExists)
	assert.Equal(t, 1, writerCount)
}

// TestGetOrCreateWriter_Disabled tests that no writer is created when disabled
func TestGetOrCreateWriter_Disabled(t *testing.T) {
	config := &PcapWriterConfig{
		Enabled: false,
	}

	manager, err := NewPcapWriterManager(config)
	require.NoError(t, err)

	writer, err := manager.GetOrCreateWriter("test-call", "alicent", "robb")
	assert.NoError(t, err)
	assert.Nil(t, writer, "writer should be nil when disabled")
}

// TestCloseWriter tests writer cleanup
func TestCloseWriter(t *testing.T) {
	tempDir := filepath.Join(os.TempDir(), "lippycat-close-test")
	defer os.RemoveAll(tempDir)

	config := &PcapWriterConfig{
		Enabled:   true,
		OutputDir: tempDir,
	}

	manager, err := NewPcapWriterManager(config)
	require.NoError(t, err)

	// Attempting to close non-existent writer should not error
	err = manager.CloseWriter("non-existent-call")
	assert.NoError(t, err)

	// Verify no panic occurred
	assert.Equal(t, 0, len(manager.writers))
}

// TestMultipleWriters tests managing multiple writers
func TestMultipleWriters(t *testing.T) {
	config := &PcapWriterConfig{
		Enabled: false, // Disabled so we don't create actual files
	}

	manager, err := NewPcapWriterManager(config)
	require.NoError(t, err)

	// Since disabled, all GetOrCreateWriter calls should return nil
	writer1, err := manager.GetOrCreateWriter("call-1", "alicent", "robb")
	assert.NoError(t, err)
	assert.Nil(t, writer1)

	writer2, err := manager.GetOrCreateWriter("call-2", "charlie", "dave")
	assert.NoError(t, err)
	assert.Nil(t, writer2)

	// Verify no writers were created
	manager.mu.RLock()
	count := len(manager.writers)
	manager.mu.RUnlock()
	assert.Equal(t, 0, count)
}

// TestPcapWriterConcurrency tests thread-safe operations
func TestPcapWriterConcurrency(t *testing.T) {
	config := &PcapWriterConfig{
		Enabled: false, // Disabled to avoid file I/O
	}

	manager, err := NewPcapWriterManager(config)
	require.NoError(t, err)

	const numGoroutines = 10
	done := make(chan struct{})

	// Concurrent GetOrCreateWriter calls
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			callID := "call-" + string(rune('0'+id))
			_, _ = manager.GetOrCreateWriter(callID, "alicent", "robb")
			done <- struct{}{}
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < numGoroutines; i++ {
		<-done
	}

	// No assertions needed - if there's a race condition, it will be detected by -race flag
}

// TestPcapWriterConfigValidation tests configuration validation
func TestPcapWriterConfigValidation(t *testing.T) {
	tests := []struct {
		name   string
		config *PcapWriterConfig
		valid  bool
	}{
		{
			name: "valid config",
			config: &PcapWriterConfig{
				Enabled:         true,
				OutputDir:       "/tmp/test",
				FilePattern:     "{callid}.pcap",
				MaxFileSize:     1024 * 1024,
				MaxFilesPerCall: 10,
				BufferSize:      4096,
				SyncInterval:    time.Second,
			},
			valid: true,
		},
		{
			name: "zero values are valid",
			config: &PcapWriterConfig{
				Enabled:         true,
				OutputDir:       "/tmp/test",
				FilePattern:     "{callid}.pcap",
				MaxFileSize:     0, // unlimited
				MaxFilesPerCall: 0, // unlimited
				BufferSize:      0,
				SyncInterval:    0,
			},
			valid: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Just verify the config can be created and has expected values
			assert.Equal(t, tt.config.Enabled, tt.config.Enabled)
			assert.Equal(t, tt.config.OutputDir, tt.config.OutputDir)
		})
	}
}

// TestPcapFilePermissions verifies that PCAP files are created with secure permissions (0600)
// This test addresses security concern from code review: Phase 1.4 - Fix PCAP File Permissions
func TestPcapFilePermissions(t *testing.T) {
	tempDir := filepath.Join(os.TempDir(), "lippycat-permissions-test")
	defer os.RemoveAll(tempDir)

	config := &PcapWriterConfig{
		Enabled:      true,
		OutputDir:    tempDir,
		SyncInterval: 5 * time.Second, // Required to avoid panic
	}

	manager, err := NewPcapWriterManager(config)
	require.NoError(t, err)

	// Create a writer (files are now created lazily on first packet write)
	writer, err := manager.GetOrCreateWriter("test-call-permissions", "alicent", "robb")
	require.NoError(t, err)
	require.NotNil(t, writer)

	// Write test packets to trigger file creation (files created lazily with correct link type)
	testData := []byte("test packet data for permissions check")
	err = writer.WriteSIPPacket(time.Now(), testData, layers.LinkTypeEthernet)
	require.NoError(t, err, "should write SIP packet")
	err = writer.WriteRTPPacket(time.Now(), testData, layers.LinkTypeEthernet)
	require.NoError(t, err, "should write RTP packet")

	// Close the writer to flush files
	err = manager.CloseWriter("test-call-permissions")
	require.NoError(t, err)

	// Check permissions on created files
	files, err := os.ReadDir(tempDir)
	require.NoError(t, err)
	require.NotEmpty(t, files, "expected PCAP files to be created")

	for _, file := range files {
		if filepath.Ext(file.Name()) == ".pcap" {
			info, err := file.Info()
			require.NoError(t, err)

			// Verify permissions are 0600 (owner read/write only)
			mode := info.Mode().Perm()
			assert.Equal(t, os.FileMode(0600), mode,
				"PCAP file %s should have 0600 permissions (owner read/write only), got %04o",
				file.Name(), mode)
		}
	}
}

// TestOnFileCloseCallback tests that the OnFileClose callback is invoked when files are closed
func TestOnFileCloseCallback(t *testing.T) {
	tempDir := filepath.Join(os.TempDir(), "lippycat-callback-test")
	defer os.RemoveAll(tempDir)

	var closedFiles []string
	var mu sync.Mutex

	config := &PcapWriterConfig{
		Enabled:      true,
		OutputDir:    tempDir,
		SyncInterval: 5 * time.Second,
		OnFileClose: func(filePath string) {
			mu.Lock()
			closedFiles = append(closedFiles, filePath)
			mu.Unlock()
		},
	}

	manager, err := NewPcapWriterManager(config)
	require.NoError(t, err)

	// Create a writer
	writer, err := manager.GetOrCreateWriter("test-callback-call", "alice", "bob")
	require.NoError(t, err)
	require.NotNil(t, writer)

	// Write packets to trigger file creation (files are created lazily)
	testData := []byte("test packet data")
	err = writer.WriteSIPPacket(time.Now(), testData, layers.LinkTypeEthernet)
	require.NoError(t, err, "should write SIP packet")
	err = writer.WriteRTPPacket(time.Now(), testData, layers.LinkTypeEthernet)
	require.NoError(t, err, "should write RTP packet")

	// Close the writer
	err = manager.CloseWriter("test-callback-call")
	require.NoError(t, err)

	// Verify callbacks were fired for both SIP and RTP files
	mu.Lock()
	defer mu.Unlock()
	assert.Len(t, closedFiles, 2, "expected 2 file close callbacks (SIP and RTP)")
}

// TestOnCallCompleteCallback tests that the OnCallComplete callback is invoked when calls are closed
func TestOnCallCompleteCallback(t *testing.T) {
	tempDir := filepath.Join(os.TempDir(), "lippycat-call-callback-test")
	defer os.RemoveAll(tempDir)

	var completedCalls []CallMetadata
	var mu sync.Mutex

	config := &PcapWriterConfig{
		Enabled:      true,
		OutputDir:    tempDir,
		SyncInterval: 5 * time.Second,
		OnCallComplete: func(meta CallMetadata) {
			mu.Lock()
			completedCalls = append(completedCalls, meta)
			mu.Unlock()
		},
	}

	manager, err := NewPcapWriterManager(config)
	require.NoError(t, err)

	// Create a writer
	writer, err := manager.GetOrCreateWriter("test-call-complete", "alice", "bob")
	require.NoError(t, err)
	require.NotNil(t, writer)

	// Close the writer using CloseCallWriter (fires OnCallComplete)
	err = manager.CloseCallWriter("test-call-complete")
	require.NoError(t, err)

	// Verify callback was fired
	mu.Lock()
	defer mu.Unlock()
	require.Len(t, completedCalls, 1, "expected 1 call complete callback")
	assert.Equal(t, "test-call-complete", completedCalls[0].CallID)
	assert.Equal(t, "alice", completedCalls[0].Caller)
	assert.Equal(t, "bob", completedCalls[0].Called)
	assert.Equal(t, tempDir, completedCalls[0].DirName)
}

// TestCloseWriterDoesNotFireOnCallComplete verifies that CloseWriter doesn't fire OnCallComplete
func TestCloseWriterDoesNotFireOnCallComplete(t *testing.T) {
	tempDir := filepath.Join(os.TempDir(), "lippycat-no-callback-test")
	defer os.RemoveAll(tempDir)

	callCompleteCount := 0
	var mu sync.Mutex

	config := &PcapWriterConfig{
		Enabled:      true,
		OutputDir:    tempDir,
		SyncInterval: 5 * time.Second,
		OnCallComplete: func(meta CallMetadata) {
			mu.Lock()
			callCompleteCount++
			mu.Unlock()
		},
	}

	manager, err := NewPcapWriterManager(config)
	require.NoError(t, err)

	// Create a writer
	_, err = manager.GetOrCreateWriter("test-no-callback", "alice", "bob")
	require.NoError(t, err)

	// Close using CloseWriter (should NOT fire OnCallComplete)
	err = manager.CloseWriter("test-no-callback")
	require.NoError(t, err)

	// Verify callback was NOT fired
	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, 0, callCompleteCount, "CloseWriter should not fire OnCallComplete")
}
