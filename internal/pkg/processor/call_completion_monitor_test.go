package processor

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/internal/pkg/voip"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultCallCompletionMonitorConfig(t *testing.T) {
	config := DefaultCallCompletionMonitorConfig()

	assert.NotNil(t, config)
	assert.Equal(t, 5*time.Second, config.GracePeriod)
	assert.Equal(t, 1*time.Second, config.CheckInterval)
}

func TestNewCallCompletionMonitor(t *testing.T) {
	tests := []struct {
		name                  string
		config                *CallCompletionMonitorConfig
		expectedGracePeriod   time.Duration
		expectedCheckInterval time.Duration
	}{
		{
			name:                  "nil config uses defaults",
			config:                nil,
			expectedGracePeriod:   5 * time.Second,
			expectedCheckInterval: 1 * time.Second,
		},
		{
			name: "custom config",
			config: &CallCompletionMonitorConfig{
				GracePeriod:   10 * time.Second,
				CheckInterval: 2 * time.Second,
			},
			expectedGracePeriod:   10 * time.Second,
			expectedCheckInterval: 2 * time.Second,
		},
		{
			name: "zero grace period gets default",
			config: &CallCompletionMonitorConfig{
				GracePeriod:   0,
				CheckInterval: 1 * time.Second,
			},
			expectedGracePeriod:   5 * time.Second,
			expectedCheckInterval: 1 * time.Second,
		},
		{
			name: "negative check interval gets default",
			config: &CallCompletionMonitorConfig{
				GracePeriod:   3 * time.Second,
				CheckInterval: -1,
			},
			expectedGracePeriod:   3 * time.Second,
			expectedCheckInterval: 1 * time.Second,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			monitor := NewCallCompletionMonitor(tt.config, nil, nil)

			assert.NotNil(t, monitor)
			assert.NotNil(t, monitor.config)
			assert.Equal(t, tt.expectedGracePeriod, monitor.config.GracePeriod)
			assert.Equal(t, tt.expectedCheckInterval, monitor.config.CheckInterval)
			assert.NotNil(t, monitor.pendingClose)
		})
	}
}

func TestCallCompletionMonitor_StartStop(t *testing.T) {
	aggregator := voip.NewCallAggregator()
	tmpDir := t.TempDir()

	pcapConfig := &PcapWriterConfig{
		Enabled:      true,
		OutputDir:    tmpDir,
		FilePattern:  "{timestamp}_{callid}.pcap",
		SyncInterval: 5 * time.Second,
	}
	pcapManager, err := NewPcapWriterManager(pcapConfig)
	require.NoError(t, err)

	config := &CallCompletionMonitorConfig{
		GracePeriod:   100 * time.Millisecond,
		CheckInterval: 50 * time.Millisecond,
	}

	monitor := NewCallCompletionMonitor(config, aggregator, pcapManager)

	// Start monitor
	monitor.Start()

	// Should be running - wait a bit
	time.Sleep(100 * time.Millisecond)

	// Stop monitor
	monitor.Stop()

	// Should stop without hanging
}

func TestCallCompletionMonitor_StartWithNilComponents(t *testing.T) {
	// Should not panic with nil aggregator
	monitor1 := NewCallCompletionMonitor(nil, nil, nil)
	monitor1.Start()
	monitor1.Stop()

	// Should not panic with nil PCAP manager
	aggregator := voip.NewCallAggregator()
	monitor2 := NewCallCompletionMonitor(nil, aggregator, nil)
	monitor2.Start()
	monitor2.Stop()
}

func TestCallCompletionMonitor_DetectsEndedCalls(t *testing.T) {
	aggregator := voip.NewCallAggregator()
	tmpDir := t.TempDir()

	pcapConfig := &PcapWriterConfig{
		Enabled:      true,
		OutputDir:    tmpDir,
		FilePattern:  "{timestamp}_{callid}.pcap",
		SyncInterval: 5 * time.Second,
	}
	pcapManager, err := NewPcapWriterManager(pcapConfig)
	require.NoError(t, err)

	// Use short intervals for testing
	config := &CallCompletionMonitorConfig{
		GracePeriod:   100 * time.Millisecond,
		CheckInterval: 50 * time.Millisecond,
	}

	monitor := NewCallCompletionMonitor(config, aggregator, pcapManager)
	monitor.Start()
	defer monitor.Stop()

	// Simulate a call that starts and ends
	callID := "test-call-001"

	// Create PCAP writer for the call
	_, err = pcapManager.GetOrCreateWriter(callID, "alice", "bob")
	require.NoError(t, err)

	// INVITE
	invitePacket := &data.CapturedPacket{
		TimestampNs: time.Now().UnixNano(),
		Metadata: &data.PacketMetadata{
			Sip: &data.SIPMetadata{
				CallId:   callID,
				Method:   "INVITE",
				FromUser: "alice",
				ToUser:   "bob",
			},
		},
	}
	aggregator.ProcessPacket(invitePacket, "hunter-1")

	// 200 OK
	okPacket := &data.CapturedPacket{
		TimestampNs: time.Now().UnixNano(),
		Metadata: &data.PacketMetadata{
			Sip: &data.SIPMetadata{
				CallId:       callID,
				Method:       "",
				ResponseCode: 200,
			},
		},
	}
	aggregator.ProcessPacket(okPacket, "hunter-1")

	// BYE
	byePacket := &data.CapturedPacket{
		TimestampNs: time.Now().UnixNano(),
		Metadata: &data.PacketMetadata{
			Sip: &data.SIPMetadata{
				CallId: callID,
				Method: "BYE",
			},
		},
	}
	aggregator.ProcessPacket(byePacket, "hunter-1")

	// Check that call is now in pending state
	time.Sleep(60 * time.Millisecond) // Wait for check interval
	assert.Greater(t, monitor.GetPendingCount(), 0, "Call should be pending closure")

	// Wait for grace period to expire
	time.Sleep(150 * time.Millisecond)

	// Call should no longer be pending
	assert.Equal(t, 0, monitor.GetPendingCount(), "Call should have been closed after grace period")
}

func TestCallCompletionMonitor_GracePeriodRespected(t *testing.T) {
	aggregator := voip.NewCallAggregator()
	tmpDir := t.TempDir()

	// Track when CloseCallWriter is called
	var closeTime atomic.Int64
	var closeCalled atomic.Int32

	pcapConfig := &PcapWriterConfig{
		Enabled:      true,
		OutputDir:    tmpDir,
		FilePattern:  "{timestamp}_{callid}.pcap",
		SyncInterval: 5 * time.Second,
	}
	pcapManager, err := NewPcapWriterManager(pcapConfig)
	require.NoError(t, err)

	// Use specific grace period
	gracePeriod := 200 * time.Millisecond
	config := &CallCompletionMonitorConfig{
		GracePeriod:   gracePeriod,
		CheckInterval: 50 * time.Millisecond,
	}

	monitor := NewCallCompletionMonitor(config, aggregator, pcapManager)
	monitor.Start()
	defer monitor.Stop()

	// Simulate a call that ends
	callID := "test-call-002"

	// Create PCAP writer for the call
	_, err = pcapManager.GetOrCreateWriter(callID, "alice", "bob")
	require.NoError(t, err)

	// Capture start time
	startTime := time.Now()

	// INVITE
	invitePacket := &data.CapturedPacket{
		TimestampNs: startTime.UnixNano(),
		Metadata: &data.PacketMetadata{
			Sip: &data.SIPMetadata{
				CallId:   callID,
				Method:   "INVITE",
				FromUser: "alice",
				ToUser:   "bob",
			},
		},
	}
	aggregator.ProcessPacket(invitePacket, "hunter-1")

	// BYE
	byePacket := &data.CapturedPacket{
		TimestampNs: startTime.UnixNano(),
		Metadata: &data.PacketMetadata{
			Sip: &data.SIPMetadata{
				CallId: callID,
				Method: "BYE",
			},
		},
	}
	aggregator.ProcessPacket(byePacket, "hunter-1")

	byeTime := time.Now()

	// Hook into the PCAP manager to track when close is called
	go func() {
		// Poll until close is called
		for {
			pcapManager.mu.RLock()
			_, exists := pcapManager.writers[callID]
			pcapManager.mu.RUnlock()

			if !exists {
				closeTime.Store(time.Now().UnixNano())
				closeCalled.Add(1)
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()

	// Wait for close to happen
	time.Sleep(gracePeriod + 100*time.Millisecond)

	// Verify close was called
	assert.Greater(t, closeCalled.Load(), int32(0), "Close should have been called")

	// Verify grace period was respected
	if closeCalled.Load() > 0 {
		closeNano := closeTime.Load()
		elapsed := time.Duration(closeNano - byeTime.UnixNano())
		// Allow some margin for timing
		assert.GreaterOrEqual(t, elapsed, gracePeriod-50*time.Millisecond,
			"Close should happen after grace period")
	}
}

func TestCallCompletionMonitor_CancelPendingClose(t *testing.T) {
	aggregator := voip.NewCallAggregator()
	tmpDir := t.TempDir()

	pcapConfig := &PcapWriterConfig{
		Enabled:      true,
		OutputDir:    tmpDir,
		FilePattern:  "{timestamp}_{callid}.pcap",
		SyncInterval: 5 * time.Second,
	}
	pcapManager, err := NewPcapWriterManager(pcapConfig)
	require.NoError(t, err)

	config := &CallCompletionMonitorConfig{
		GracePeriod:   500 * time.Millisecond, // Long grace period
		CheckInterval: 50 * time.Millisecond,
	}

	monitor := NewCallCompletionMonitor(config, aggregator, pcapManager)
	monitor.Start()
	defer monitor.Stop()

	// Simulate a call that ends
	callID := "test-call-003"

	// Create PCAP writer for the call
	_, err = pcapManager.GetOrCreateWriter(callID, "alice", "bob")
	require.NoError(t, err)

	// INVITE
	invitePacket := &data.CapturedPacket{
		TimestampNs: time.Now().UnixNano(),
		Metadata: &data.PacketMetadata{
			Sip: &data.SIPMetadata{
				CallId:   callID,
				Method:   "INVITE",
				FromUser: "alice",
				ToUser:   "bob",
			},
		},
	}
	aggregator.ProcessPacket(invitePacket, "hunter-1")

	// BYE
	byePacket := &data.CapturedPacket{
		TimestampNs: time.Now().UnixNano(),
		Metadata: &data.PacketMetadata{
			Sip: &data.SIPMetadata{
				CallId: callID,
				Method: "BYE",
			},
		},
	}
	aggregator.ProcessPacket(byePacket, "hunter-1")

	// Wait for call to be scheduled for closure
	time.Sleep(100 * time.Millisecond)
	assert.Greater(t, monitor.GetPendingCount(), 0, "Call should be pending closure")

	// Cancel the pending close
	monitor.CancelPendingClose(callID)

	// Verify pending count decreased
	assert.Equal(t, 0, monitor.GetPendingCount(), "Call should no longer be pending")
}

func TestCallCompletionMonitor_MultipleCalls(t *testing.T) {
	aggregator := voip.NewCallAggregator()
	tmpDir := t.TempDir()

	pcapConfig := &PcapWriterConfig{
		Enabled:      true,
		OutputDir:    tmpDir,
		FilePattern:  "{timestamp}_{callid}.pcap",
		SyncInterval: 5 * time.Second,
	}
	pcapManager, err := NewPcapWriterManager(pcapConfig)
	require.NoError(t, err)

	config := &CallCompletionMonitorConfig{
		GracePeriod:   100 * time.Millisecond,
		CheckInterval: 50 * time.Millisecond,
	}

	monitor := NewCallCompletionMonitor(config, aggregator, pcapManager)
	monitor.Start()
	defer monitor.Stop()

	// Create multiple calls
	callIDs := []string{"call-1", "call-2", "call-3"}

	for _, callID := range callIDs {
		// Create PCAP writer for the call
		_, err = pcapManager.GetOrCreateWriter(callID, "alice", "bob")
		require.NoError(t, err)

		// INVITE
		invitePacket := &data.CapturedPacket{
			TimestampNs: time.Now().UnixNano(),
			Metadata: &data.PacketMetadata{
				Sip: &data.SIPMetadata{
					CallId:   callID,
					Method:   "INVITE",
					FromUser: "alice",
					ToUser:   "bob",
				},
			},
		}
		aggregator.ProcessPacket(invitePacket, "hunter-1")
	}

	// End all calls
	for _, callID := range callIDs {
		byePacket := &data.CapturedPacket{
			TimestampNs: time.Now().UnixNano(),
			Metadata: &data.PacketMetadata{
				Sip: &data.SIPMetadata{
					CallId: callID,
					Method: "BYE",
				},
			},
		}
		aggregator.ProcessPacket(byePacket, "hunter-1")
	}

	// Wait for calls to be scheduled
	time.Sleep(100 * time.Millisecond)
	assert.Equal(t, 3, monitor.GetPendingCount(), "All 3 calls should be pending closure")

	// Wait for grace period
	time.Sleep(150 * time.Millisecond)
	assert.Equal(t, 0, monitor.GetPendingCount(), "All calls should have been closed")
}

func TestCallCompletionMonitor_ShutdownClosesPending(t *testing.T) {
	aggregator := voip.NewCallAggregator()
	tmpDir := t.TempDir()

	pcapConfig := &PcapWriterConfig{
		Enabled:      true,
		OutputDir:    tmpDir,
		FilePattern:  "{timestamp}_{callid}.pcap",
		SyncInterval: 5 * time.Second,
	}
	pcapManager, err := NewPcapWriterManager(pcapConfig)
	require.NoError(t, err)

	config := &CallCompletionMonitorConfig{
		GracePeriod:   1 * time.Hour, // Very long grace period
		CheckInterval: 50 * time.Millisecond,
	}

	monitor := NewCallCompletionMonitor(config, aggregator, pcapManager)
	monitor.Start()

	// Create a call and end it
	callID := "test-call-shutdown"

	_, err = pcapManager.GetOrCreateWriter(callID, "alice", "bob")
	require.NoError(t, err)

	invitePacket := &data.CapturedPacket{
		TimestampNs: time.Now().UnixNano(),
		Metadata: &data.PacketMetadata{
			Sip: &data.SIPMetadata{
				CallId:   callID,
				Method:   "INVITE",
				FromUser: "alice",
				ToUser:   "bob",
			},
		},
	}
	aggregator.ProcessPacket(invitePacket, "hunter-1")

	byePacket := &data.CapturedPacket{
		TimestampNs: time.Now().UnixNano(),
		Metadata: &data.PacketMetadata{
			Sip: &data.SIPMetadata{
				CallId: callID,
				Method: "BYE",
			},
		},
	}
	aggregator.ProcessPacket(byePacket, "hunter-1")

	// Wait for call to be scheduled
	time.Sleep(100 * time.Millisecond)
	assert.Greater(t, monitor.GetPendingCount(), 0, "Call should be pending closure")

	// Stop the monitor - should close pending calls immediately
	monitor.Stop()

	// Verify PCAP writer was closed (call removed from manager)
	pcapManager.mu.RLock()
	_, exists := pcapManager.writers[callID]
	pcapManager.mu.RUnlock()

	assert.False(t, exists, "PCAP writer should have been closed on shutdown")
}

func TestCallCompletionMonitor_GetPendingCount_NilMonitor(t *testing.T) {
	var monitor *CallCompletionMonitor
	assert.Equal(t, 0, monitor.GetPendingCount())
}

func TestCallCompletionMonitor_CancelPendingClose_NilMonitor(t *testing.T) {
	var monitor *CallCompletionMonitor
	// Should not panic
	monitor.CancelPendingClose("test-call")
}

func TestCallCompletionMonitor_ConcurrentAccess(t *testing.T) {
	aggregator := voip.NewCallAggregator()
	tmpDir := t.TempDir()

	pcapConfig := &PcapWriterConfig{
		Enabled:      true,
		OutputDir:    tmpDir,
		FilePattern:  "{timestamp}_{callid}.pcap",
		SyncInterval: 5 * time.Second,
	}
	pcapManager, err := NewPcapWriterManager(pcapConfig)
	require.NoError(t, err)

	config := &CallCompletionMonitorConfig{
		GracePeriod:   50 * time.Millisecond,
		CheckInterval: 10 * time.Millisecond,
	}

	monitor := NewCallCompletionMonitor(config, aggregator, pcapManager)
	monitor.Start()
	defer monitor.Stop()

	// Concurrent operations
	var wg sync.WaitGroup
	numGoroutines := 10

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()

			callID := "concurrent-call-" + string(rune('0'+idx))

			// Create PCAP writer
			_, err := pcapManager.GetOrCreateWriter(callID, "alice", "bob")
			if err != nil {
				return
			}

			// Simulate call
			invitePacket := &data.CapturedPacket{
				TimestampNs: time.Now().UnixNano(),
				Metadata: &data.PacketMetadata{
					Sip: &data.SIPMetadata{
						CallId:   callID,
						Method:   "INVITE",
						FromUser: "alice",
						ToUser:   "bob",
					},
				},
			}
			aggregator.ProcessPacket(invitePacket, "hunter-1")

			// End call
			byePacket := &data.CapturedPacket{
				TimestampNs: time.Now().UnixNano(),
				Metadata: &data.PacketMetadata{
					Sip: &data.SIPMetadata{
						CallId: callID,
						Method: "BYE",
					},
				},
			}
			aggregator.ProcessPacket(byePacket, "hunter-1")

			// Random operations
			_ = monitor.GetPendingCount()
			if idx%2 == 0 {
				monitor.CancelPendingClose(callID)
			}
		}(i)
	}

	wg.Wait()

	// Wait for cleanup
	time.Sleep(100 * time.Millisecond)
}

func TestCallCompletionMonitor_FailedCallStateDetection(t *testing.T) {
	aggregator := voip.NewCallAggregator()
	tmpDir := t.TempDir()

	pcapConfig := &PcapWriterConfig{
		Enabled:      true,
		OutputDir:    tmpDir,
		FilePattern:  "{timestamp}_{callid}.pcap",
		SyncInterval: 5 * time.Second,
	}
	pcapManager, err := NewPcapWriterManager(pcapConfig)
	require.NoError(t, err)

	config := &CallCompletionMonitorConfig{
		GracePeriod:   100 * time.Millisecond,
		CheckInterval: 50 * time.Millisecond,
	}

	monitor := NewCallCompletionMonitor(config, aggregator, pcapManager)
	monitor.Start()
	defer monitor.Stop()

	callID := "test-call-failed"

	// Create PCAP writer for the call
	_, err = pcapManager.GetOrCreateWriter(callID, "alice", "bob")
	require.NoError(t, err)

	// INVITE
	invitePacket := &data.CapturedPacket{
		TimestampNs: time.Now().UnixNano(),
		Metadata: &data.PacketMetadata{
			Sip: &data.SIPMetadata{
				CallId:   callID,
				Method:   "INVITE",
				FromUser: "alice",
				ToUser:   "bob",
			},
		},
	}
	aggregator.ProcessPacket(invitePacket, "hunter-1")

	// CANCEL (call failed)
	cancelPacket := &data.CapturedPacket{
		TimestampNs: time.Now().UnixNano(),
		Metadata: &data.PacketMetadata{
			Sip: &data.SIPMetadata{
				CallId: callID,
				Method: "CANCEL",
			},
		},
	}
	aggregator.ProcessPacket(cancelPacket, "hunter-1")

	// Wait for call to be scheduled for closure
	time.Sleep(100 * time.Millisecond)
	assert.Greater(t, monitor.GetPendingCount(), 0, "Failed call should be pending closure")

	// Wait for grace period
	time.Sleep(150 * time.Millisecond)
	assert.Equal(t, 0, monitor.GetPendingCount(), "Failed call should have been closed")
}
