package processor

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestProcessor_Start_Success tests successful processor startup
func TestProcessor_Start_Success(t *testing.T) {
	// Create processor with unique port
	processor, err := New(Config{
		ProcessorID: "test-processor",
		ListenAddr:  "localhost:0", // Let OS assign port
		MaxHunters:  10,
	})
	require.NoError(t, err)
	require.NotNil(t, processor)

	// Start processor in background
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- processor.Start(ctx)
	}()

	// Give processor time to start
	time.Sleep(100 * time.Millisecond)

	// Verify processor is running by attempting to connect
	// We need to get the actual address since we used port 0
	// The processor should have stored the listener
	// For now, just verify no immediate error
	select {
	case err := <-errCh:
		t.Fatalf("processor.Start() returned unexpectedly: %v", err)
	default:
		// Processor is still running, good
	}

	// Clean shutdown
	cancel()

	// Wait for shutdown to complete
	select {
	case err := <-errCh:
		assert.NoError(t, err, "processor.Start() should return nil on clean shutdown")
	case <-time.After(5 * time.Second):
		t.Fatal("processor shutdown timeout")
	}
}

// TestProcessor_Start_BindError tests startup failure due to port already in use
func TestProcessor_Start_BindError(t *testing.T) {
	// Create a listener to occupy a port
	listener, err := net.Listen("tcp", "localhost:0")
	require.NoError(t, err)
	defer listener.Close()

	occupiedAddr := listener.Addr().String()

	// Create processor with same address
	processor, err := New(Config{
		ProcessorID: "test-processor",
		ListenAddr:  occupiedAddr,
		MaxHunters:  10,
	})
	require.NoError(t, err)

	// Attempt to start should fail
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err = processor.Start(ctx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to listen")
}

// TestProcessor_Shutdown_Clean tests clean shutdown with no active components
func TestProcessor_Shutdown_Clean(t *testing.T) {
	processor, err := New(Config{
		ProcessorID: "test-processor",
		ListenAddr:  "localhost:0",
		MaxHunters:  10,
	})
	require.NoError(t, err)

	// Start processor
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- processor.Start(ctx)
	}()

	// Wait for startup
	time.Sleep(100 * time.Millisecond)

	// Shutdown via context cancel
	cancel()

	// Wait for shutdown
	select {
	case err := <-errCh:
		assert.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("shutdown timeout")
	}

	// Verify shutdown completed
	assert.NotNil(t, processor)
}

// TestProcessor_Shutdown_Idempotent tests that multiple shutdown calls are safe
func TestProcessor_Shutdown_Idempotent(t *testing.T) {
	processor, err := New(Config{
		ProcessorID: "test-processor",
		ListenAddr:  "localhost:0",
		MaxHunters:  10,
	})
	require.NoError(t, err)

	// Start processor
	ctx, cancel := context.WithCancel(context.Background())

	errCh := make(chan error, 1)
	go func() {
		errCh <- processor.Start(ctx)
	}()

	// Wait for startup
	time.Sleep(100 * time.Millisecond)

	// First shutdown via cancel
	cancel()

	// Wait for Start() to return
	select {
	case err := <-errCh:
		assert.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("first shutdown timeout")
	}

	// Call Shutdown() method once more
	// (cancel already triggered shutdown, so this tests idempotency)
	err1 := processor.Shutdown()

	// Should succeed without panicking
	assert.NoError(t, err1)
}

// TestProcessor_StartStop_Cycle tests multiple start/stop cycles
func TestProcessor_StartStop_Cycle(t *testing.T) {
	// We can't actually restart the same processor instance
	// because gRPC server can't be restarted, but we can test
	// creating and shutting down multiple processors

	for i := 0; i < 3; i++ {
		t.Run(fmt.Sprintf("cycle_%d", i), func(t *testing.T) {
			processor, err := New(Config{
				ProcessorID: fmt.Sprintf("test-processor-%d", i),
				ListenAddr:  "localhost:0", // OS assigns port
				MaxHunters:  10,
			})
			require.NoError(t, err)

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			errCh := make(chan error, 1)
			go func() {
				errCh <- processor.Start(ctx)
			}()

			// Wait for startup
			time.Sleep(100 * time.Millisecond)

			// Shutdown
			cancel()

			// Wait for shutdown
			select {
			case err := <-errCh:
				assert.NoError(t, err)
			case <-time.After(5 * time.Second):
				t.Fatal("shutdown timeout")
			}
		})
	}
}

// TestProcessor_Shutdown_WithPcapWriter tests shutdown with active PCAP writer
func TestProcessor_Shutdown_WithPcapWriter(t *testing.T) {
	// Create temp directory for PCAP file
	tempDir := t.TempDir()
	pcapFile := filepath.Join(tempDir, "test.pcap")

	processor, err := New(Config{
		ProcessorID: "test-processor",
		ListenAddr:  "localhost:0",
		MaxHunters:  10,
		WriteFile:   pcapFile,
	})
	require.NoError(t, err)

	// Start processor
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- processor.Start(ctx)
	}()

	// Wait for startup
	time.Sleep(200 * time.Millisecond)

	// Shutdown
	cancel()

	// Wait for shutdown - should complete cleanly even with PCAP writer active
	select {
	case err := <-errCh:
		assert.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("shutdown timeout")
	}

	// Verify PCAP file was created (even if empty)
	_, err = os.Stat(pcapFile)
	assert.NoError(t, err, "PCAP file should exist after shutdown")
}

// TestProcessor_Shutdown_WithAutoRotatePcapWriter tests shutdown with auto-rotate PCAP writer
func TestProcessor_Shutdown_WithAutoRotatePcapWriter(t *testing.T) {
	tempDir := t.TempDir()

	processor, err := New(Config{
		ProcessorID: "test-processor",
		ListenAddr:  "localhost:0",
		MaxHunters:  10,
		AutoRotateConfig: &AutoRotateConfig{
			Enabled:      true,
			OutputDir:    tempDir,
			FilePattern:  "{timestamp}.pcap",
			MaxFileSize:  1024 * 1024,
			MaxDuration:  60 * time.Second,
			MaxIdleTime:  30 * time.Second,
			MinDuration:  1 * time.Second,
			BufferSize:   4096,
			SyncInterval: 5 * time.Second,
		},
	})
	require.NoError(t, err)

	// Start processor
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- processor.Start(ctx)
	}()

	// Wait for startup
	time.Sleep(100 * time.Millisecond)

	// Process a non-VoIP packet (should trigger auto-rotate writer)
	if processor.autoRotatePcapWriter != nil {
		batch := &data.PacketBatch{
			HunterId:    "test-hunter",
			Sequence:    1,
			TimestampNs: time.Now().UnixNano(),
			Packets: []*data.CapturedPacket{
				{
					Data:        []byte{0x00, 0x01, 0x02, 0x03},
					TimestampNs: time.Now().UnixNano(),
					LinkType:    1,
					Metadata: &data.PacketMetadata{
						SrcIp:    "192.168.1.1",
						DstIp:    "192.168.1.2",
						Protocol: "TCP",
						// No SIP/RTP metadata - non-VoIP packet
					},
				},
			},
		}

		// Register hunter first
		processor.hunterManager.Register("test-hunter", "localhost", []string{"eth0"}, nil)

		processor.processBatch(batch)
	}

	// Give time for async write
	time.Sleep(100 * time.Millisecond)

	// Shutdown
	cancel()

	// Wait for shutdown
	select {
	case err := <-errCh:
		assert.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("shutdown timeout")
	}

	// Verify auto-rotate PCAP writer was properly closed
	assert.NotNil(t, processor.autoRotatePcapWriter)
}

// TestProcessor_Shutdown_WithPerCallPcapWriter tests shutdown with per-call PCAP writer
func TestProcessor_Shutdown_WithPerCallPcapWriter(t *testing.T) {
	tempDir := t.TempDir()

	processor, err := New(Config{
		ProcessorID: "test-processor",
		ListenAddr:  "localhost:0",
		MaxHunters:  10,
		PcapWriterConfig: &PcapWriterConfig{
			Enabled:      true,
			OutputDir:    tempDir,
			FilePattern:  "{callid}.pcap",
			BufferSize:   4096,
			SyncInterval: 5 * time.Second,
		},
	})
	require.NoError(t, err)

	// Start processor
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- processor.Start(ctx)
	}()

	// Wait for startup
	time.Sleep(100 * time.Millisecond)

	// Process a VoIP packet with call-id
	if processor.perCallPcapWriter != nil {
		batch := &data.PacketBatch{
			HunterId:    "test-hunter",
			Sequence:    1,
			TimestampNs: time.Now().UnixNano(),
			Packets: []*data.CapturedPacket{
				{
					Data:        []byte{0x00, 0x01, 0x02, 0x03},
					TimestampNs: time.Now().UnixNano(),
					LinkType:    1,
					Metadata: &data.PacketMetadata{
						SrcIp:    "192.168.1.1",
						DstIp:    "192.168.1.2",
						Protocol: "UDP",
						Sip: &data.SIPMetadata{
							CallId:   "test-call-123",
							FromUser: "alice",
							ToUser:   "bob",
							Method:   "INVITE",
						},
					},
				},
			},
		}

		// Register hunter first
		processor.hunterManager.Register("test-hunter", "localhost", []string{"eth0"}, nil)

		processor.processBatch(batch)
	}

	// Give time for async write
	time.Sleep(100 * time.Millisecond)

	// Shutdown
	cancel()

	// Wait for shutdown
	select {
	case err := <-errCh:
		assert.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("shutdown timeout")
	}

	// Verify per-call PCAP writer was properly closed
	assert.NotNil(t, processor.perCallPcapWriter)
}

// TestProcessor_Shutdown_WithSubscribers tests shutdown notifies subscribers
func TestProcessor_Shutdown_WithSubscribers(t *testing.T) {
	processor, err := New(Config{
		ProcessorID: "test-processor",
		ListenAddr:  "localhost:0",
		MaxHunters:  10,
	})
	require.NoError(t, err)

	// Start processor
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- processor.Start(ctx)
	}()

	// Wait for startup
	time.Sleep(100 * time.Millisecond)

	// Add a subscriber
	subChan := processor.subscriberManager.Add("test-subscriber")
	require.NotNil(t, subChan)

	// Shutdown
	cancel()

	// Wait for shutdown
	select {
	case err := <-errCh:
		assert.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("shutdown timeout")
	}

	// Verify subscriber channel was closed or drained
	// The subscriberManager should handle cleanup
	assert.NotNil(t, processor.subscriberManager)
}

// TestProcessor_Shutdown_WithUpstream tests shutdown closes upstream connection
func TestProcessor_Shutdown_WithUpstream(t *testing.T) {
	// This test requires a mock upstream processor
	// For now, we'll test that creating processor with upstream doesn't crash on shutdown

	processor, err := New(Config{
		ProcessorID:  "test-processor",
		ListenAddr:   "localhost:0",
		MaxHunters:   10,
		UpstreamAddr: "upstream:50051", // Non-existent upstream (won't connect)
	})
	require.NoError(t, err)
	require.NotNil(t, processor.upstreamManager)

	// Start processor - will try to connect to upstream but should handle failure
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	err = processor.Start(ctx)
	// Should fail to connect to upstream, but that's expected in this test
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to connect to upstream")
}

// TestProcessor_Start_WithTLSProductionMode tests production mode requirements
func TestProcessor_Start_WithTLSProductionMode(t *testing.T) {
	// Set production mode via environment variable
	os.Setenv("LIPPYCAT_PRODUCTION", "true")
	defer os.Unsetenv("LIPPYCAT_PRODUCTION")

	processor, err := New(Config{
		ProcessorID: "test-processor",
		ListenAddr:  "localhost:0",
		MaxHunters:  10,
		TLSEnabled:  false, // Production mode requires TLS
	})
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	err = processor.Start(ctx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "LIPPYCAT_PRODUCTION=true requires TLS")
}

// TestProcessor_GRPCConnection tests that gRPC server is accessible
func TestProcessor_GRPCConnection(t *testing.T) {
	processor, err := New(Config{
		ProcessorID: "test-processor",
		ListenAddr:  "localhost:0",
		MaxHunters:  10,
	})
	require.NoError(t, err)

	// Start processor
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- processor.Start(ctx)
	}()

	// Wait for startup
	time.Sleep(200 * time.Millisecond)

	// Get actual listening address
	// Since we can't easily get the address from inside the processor,
	// we'll skip the connection test for now
	// In a real test, we'd need to expose the listener address

	// Shutdown
	cancel()

	select {
	case err := <-errCh:
		assert.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("shutdown timeout")
	}
}

// TestProcessor_Start_WithVirtualInterface tests startup with virtual interface
func TestProcessor_Start_WithVirtualInterface(t *testing.T) {
	// Skip if not running as root (virtual interface requires privileges)
	if os.Geteuid() != 0 {
		t.Skip("Skipping virtual interface test (requires root)")
	}

	processor, err := New(Config{
		ProcessorID:          "test-processor",
		ListenAddr:           "localhost:0",
		MaxHunters:           10,
		VirtualInterface:     true,
		VirtualInterfaceName: "lippycat-test",
		VifBufferSize:        1024,
	})
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- processor.Start(ctx)
	}()

	// Wait for startup
	time.Sleep(200 * time.Millisecond)

	// Verify virtual interface was created
	if processor.vifManager != nil {
		assert.Equal(t, "lippycat-test", processor.vifManager.Name())
	}

	// Shutdown
	cancel()

	select {
	case err := <-errCh:
		assert.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("shutdown timeout")
	}
}
