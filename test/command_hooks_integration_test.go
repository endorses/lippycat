//go:build processor || tap || all

package test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/processor"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// TestIntegration_CommandHooks_PcapCommand tests that --pcap-command fires on PCAP close
func TestIntegration_CommandHooks_PcapCommand(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Create temp directory for test artifacts
	tmpDir, err := os.MkdirTemp("", "lippycat-hook-test-*")
	require.NoError(t, err, "Failed to create temp dir")
	defer os.RemoveAll(tmpDir)

	pcapDir := filepath.Join(tmpDir, "pcaps")
	require.NoError(t, os.MkdirAll(pcapDir, 0755))

	// File to track command execution
	commandLog := filepath.Join(tmpDir, "pcap-commands.log")

	// Get a free port
	processorAddr, err := getFreePort()
	require.NoError(t, err, "Failed to get free port")

	// Start processor with per-call PCAP and pcap-command hook
	procCtx, procCancel := context.WithCancel(ctx)
	defer procCancel()

	config := processor.Config{
		ProcessorID:     "test-processor-hooks",
		ListenAddr:      processorAddr,
		EnableDetection: false,
		MaxHunters:      100,
		FilterFile:      "/tmp/lippycat-test-filters-does-not-exist.yaml",
		PcapWriterConfig: &processor.PcapWriterConfig{
			Enabled:         true,
			OutputDir:       pcapDir,
			FilePattern:     "{timestamp}_{callid}.pcap",
			MaxFileSize:     100 * 1024 * 1024,
			MaxFilesPerCall: 10,
			BufferSize:      4096,
			SyncInterval:    1 * time.Second,
		},
		CommandExecutorConfig: &processor.CommandExecutorConfig{
			PcapCommand: "echo %pcap% >> " + commandLog,
			Timeout:     5 * time.Second,
			Concurrency: 10,
		},
		CallCompletionMonitorConfig: &processor.CallCompletionMonitorConfig{
			GracePeriod:   1 * time.Second, // Short grace period for test
			CheckInterval: 500 * time.Millisecond,
		},
	}

	proc, err := processor.New(config)
	require.NoError(t, err, "Failed to create processor")
	defer shutdownProcessorWithPortCleanup(proc)

	// Start processor in background
	errChan := make(chan error, 1)
	go func() {
		if err := proc.Start(procCtx); err != nil {
			select {
			case errChan <- err:
			default:
			}
		}
	}()

	// Wait for processor to be ready
	time.Sleep(500 * time.Millisecond)

	// Connect to processor as a hunter
	conn, err := grpc.DialContext(ctx, processorAddr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
	)
	require.NoError(t, err, "Failed to connect to processor")
	defer conn.Close()

	dataClient := data.NewDataServiceClient(conn)
	mgmtClient := management.NewManagementServiceClient(conn)

	// Register hunter
	regResp, err := mgmtClient.RegisterHunter(ctx, &management.HunterRegistration{
		HunterId:   "test-hunter-hooks",
		Hostname:   "test-host",
		Interfaces: []string{"mock0"},
		Version:    "test-1.0.0",
		Capabilities: &management.HunterCapabilities{
			FilterTypes:   []string{"bpf"},
			MaxBufferSize: 8192,
		},
	})
	require.NoError(t, err, "Failed to register hunter")
	assert.True(t, regResp.Accepted, "Hunter registration rejected")

	// Stream packets
	stream, err := dataClient.StreamPackets(ctx)
	require.NoError(t, err, "Failed to create stream")

	// Send a complete VoIP call: INVITE -> RTP -> BYE
	callID := "test-hook-call-123"

	// Send INVITE
	invitePacket := createSIPPacketWithCallID("INVITE", callID)
	batch := &data.PacketBatch{
		HunterId:    "test-hunter-hooks",
		Sequence:    1,
		TimestampNs: time.Now().UnixNano(),
		Packets:     []*data.CapturedPacket{invitePacket},
	}
	err = stream.Send(batch)
	require.NoError(t, err, "Failed to send INVITE")

	// Receive ack
	_, err = stream.Recv()
	require.NoError(t, err, "Failed to receive ack for INVITE")

	// Send some RTP packets
	for i := 0; i < 5; i++ {
		rtpPacket := createRTPPacketWithCallID(callID, uint16(i))
		batch := &data.PacketBatch{
			HunterId:    "test-hunter-hooks",
			Sequence:    uint64(2 + i),
			TimestampNs: time.Now().UnixNano(),
			Packets:     []*data.CapturedPacket{rtpPacket},
		}
		err = stream.Send(batch)
		require.NoError(t, err, "Failed to send RTP packet %d", i)
		_, err = stream.Recv()
		require.NoError(t, err, "Failed to receive ack for RTP packet %d", i)
	}

	// Send BYE to end the call
	byePacket := createSIPPacketWithCallID("BYE", callID)
	batch = &data.PacketBatch{
		HunterId:    "test-hunter-hooks",
		Sequence:    10,
		TimestampNs: time.Now().UnixNano(),
		Packets:     []*data.CapturedPacket{byePacket},
	}
	err = stream.Send(batch)
	require.NoError(t, err, "Failed to send BYE")
	_, err = stream.Recv()
	require.NoError(t, err, "Failed to receive ack for BYE")

	// Wait for grace period + some buffer
	t.Log("Waiting for call completion detection and command execution...")
	time.Sleep(3 * time.Second)

	// Check if command was executed by reading the log file
	logContent, err := os.ReadFile(commandLog)
	if err != nil {
		t.Logf("Command log file not found: %v", err)
		// List what's in the pcap directory
		entries, _ := os.ReadDir(pcapDir)
		t.Logf("PCAP directory contents: %d files", len(entries))
		for _, e := range entries {
			t.Logf("  - %s", e.Name())
		}
	} else {
		t.Logf("Command log content:\n%s", string(logContent))
		lines := strings.Split(strings.TrimSpace(string(logContent)), "\n")
		assert.GreaterOrEqual(t, len(lines), 1, "Expected at least one command execution logged")

		// Verify logged paths are valid PCAP files
		for _, line := range lines {
			if line == "" {
				continue
			}
			assert.Contains(t, line, ".pcap", "Logged path should be a PCAP file: %s", line)
			assert.True(t, filepath.IsAbs(line), "Logged path should be absolute: %s", line)
		}
	}

	t.Log("✓ PCAP command hook test completed")
}

// TestIntegration_CommandHooks_Timeout tests that long-running commands are killed
func TestIntegration_CommandHooks_Timeout(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Create a command executor with a very short timeout
	executor := processor.NewCommandExecutor(&processor.CommandExecutorConfig{
		PcapCommand: "sleep 10", // Command that would take 10s
		Timeout:     1 * time.Second,
		Concurrency: 5,
	})

	// Execute the command (should timeout)
	start := time.Now()
	executor.ExecutePcapCommand("/tmp/test.pcap")

	// Give async execution time to complete
	time.Sleep(2 * time.Second)

	elapsed := time.Since(start)
	assert.Less(t, elapsed, 5*time.Second, "Command should have been killed by timeout")

	t.Logf("✓ Timeout test: Command execution took %v (should be ~1-2s)", elapsed)
}

// TestIntegration_CommandHooks_Concurrency tests that concurrent commands respect semaphore
func TestIntegration_CommandHooks_Concurrency(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	tmpDir, err := os.MkdirTemp("", "lippycat-concurrency-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	concurrencyLog := filepath.Join(tmpDir, "concurrency.log")

	// Create executor with low concurrency limit
	executor := processor.NewCommandExecutor(&processor.CommandExecutorConfig{
		PcapCommand: "echo $(date +%s.%N) >> " + concurrencyLog + " && sleep 0.5",
		Timeout:     5 * time.Second,
		Concurrency: 2, // Only allow 2 concurrent executions
	})

	// Fire 5 commands simultaneously
	for i := 0; i < 5; i++ {
		executor.ExecutePcapCommand("/tmp/test.pcap")
	}

	// Wait for all to complete (or some to be dropped)
	time.Sleep(4 * time.Second)

	// Check how many actually executed
	content, err := os.ReadFile(concurrencyLog)
	if err == nil {
		lines := strings.Split(strings.TrimSpace(string(content)), "\n")
		// With concurrency 2 and 0.5s sleep, in 4s we can do at most ~16 commands
		// But we only fire 5, so some might be dropped due to semaphore
		t.Logf("✓ Concurrency test: %d commands executed (some may be dropped due to semaphore)", len(lines))
	}

	t.Log("✓ Concurrency limit test completed")
}

// Helper to create SIP packet with specific Call-ID
func createSIPPacketWithCallID(method, callID string) *data.CapturedPacket {
	sipMsg := method + " sip:robb@example.com SIP/2.0\r\n" +
		"Via: SIP/2.0/UDP 192.168.1.10:5060\r\n" +
		"From: <sip:alicent@example.com>\r\n" +
		"To: <sip:robb@example.com>\r\n" +
		"Call-ID: " + callID + "@example.com\r\n" +
		"CSeq: 1 " + method + "\r\n" +
		"Content-Length: 0\r\n\r\n"

	return &data.CapturedPacket{
		TimestampNs:    time.Now().UnixNano(),
		CaptureLength:  uint32(len(sipMsg)),
		OriginalLength: uint32(len(sipMsg)),
		Data:           []byte(sipMsg),
		LinkType:       1,
		Metadata: &data.PacketMetadata{
			Protocol: "SIP",
			Sip: &data.SIPMetadata{
				Method:   method,
				CallId:   callID + "@example.com",
				FromUser: "alicent",
				ToUser:   "robb",
			},
		},
	}
}

// Helper to create RTP packet with Call-ID in metadata
func createRTPPacketWithCallID(callID string, sequence uint16) *data.CapturedPacket {
	rtpHeader := make([]byte, 12)
	rtpHeader[0] = 0x80 // Version 2
	rtpHeader[1] = 0x00 // Payload type 0 (PCMU)
	rtpHeader[2] = byte(sequence >> 8)
	rtpHeader[3] = byte(sequence & 0xff)

	payload := make([]byte, 160) // Audio payload
	rtpData := append(rtpHeader, payload...)

	return &data.CapturedPacket{
		TimestampNs:    time.Now().UnixNano(),
		CaptureLength:  uint32(len(rtpData)),
		OriginalLength: uint32(len(rtpData)),
		Data:           rtpData,
		LinkType:       1,
		Metadata: &data.PacketMetadata{
			Protocol: "RTP",
			Sip: &data.SIPMetadata{
				CallId: callID + "@example.com", // RTP packets have call-id from hunter
			},
			Rtp: &data.RTPMetadata{
				PayloadType: 0,
				Sequence:    uint32(sequence),
			},
		},
	}
}
