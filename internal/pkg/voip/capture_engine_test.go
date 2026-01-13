//go:build cli || all

package voip

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultCaptureConfig(t *testing.T) {
	config := DefaultCaptureConfig("eth0")

	assert.Equal(t, "eth0", config.Interface)
	assert.True(t, config.UseXDP)
	assert.Equal(t, 0, config.XDPQueueID)
	assert.Equal(t, 65536, config.SnapLen)
	assert.True(t, config.Promiscuous)
	assert.Equal(t, 1000, config.BufferSize)
	assert.Equal(t, 64, config.BatchSize)
	assert.Equal(t, 100*time.Millisecond, config.Timeout)
	assert.True(t, config.EnableStats)
	assert.Equal(t, 10*time.Second, config.StatsInterval)
}

func TestCaptureEngine_Creation(t *testing.T) {
	config := DefaultCaptureConfig("lo")
	config.UseXDP = false // Use standard for testing

	engine, err := NewCaptureEngine(config)
	require.NoError(t, err)
	defer engine.Close()

	assert.NotNil(t, engine)
	assert.Equal(t, CaptureModeStandard, engine.GetMode())
}

func TestCaptureEngine_NilConfig(t *testing.T) {
	engine, err := NewCaptureEngine(nil)
	require.NoError(t, err)
	defer engine.Close()

	assert.NotNil(t, engine)
}

func TestCaptureEngine_Start_Stop(t *testing.T) {
	config := DefaultCaptureConfig("lo")
	config.UseXDP = false

	engine, err := NewCaptureEngine(config)
	require.NoError(t, err)
	defer engine.Close()

	// Start
	err = engine.Start()
	assert.NoError(t, err)

	// Wait a bit
	time.Sleep(100 * time.Millisecond)

	// Stop
	err = engine.Stop()
	assert.NoError(t, err)

	// After stop, start again should work since context is reset
	// (This is different from the old behavior)
}

func TestCaptureEngine_DoubleStart(t *testing.T) {
	config := DefaultCaptureConfig("lo")
	config.UseXDP = false

	engine, err := NewCaptureEngine(config)
	require.NoError(t, err)
	defer engine.Close()

	err = engine.Start()
	assert.NoError(t, err)

	// Try to start again - should fail
	err = engine.Start()
	assert.Error(t, err)

	engine.Stop()
}

func TestCaptureEngine_DoubleStop(t *testing.T) {
	config := DefaultCaptureConfig("lo")
	config.UseXDP = false

	engine, err := NewCaptureEngine(config)
	require.NoError(t, err)
	defer engine.Close()

	err = engine.Start()
	assert.NoError(t, err)

	err = engine.Stop()
	assert.NoError(t, err)

	// Try to stop again - should fail
	err = engine.Stop()
	assert.Error(t, err)
}

func TestCaptureEngine_Packets(t *testing.T) {
	config := DefaultCaptureConfig("lo")
	config.UseXDP = false
	config.BufferSize = 100

	engine, err := NewCaptureEngine(config)
	require.NoError(t, err)
	defer engine.Close()

	packetChan := engine.Packets()
	assert.NotNil(t, packetChan)
}

func TestCaptureEngine_GetStats(t *testing.T) {
	config := DefaultCaptureConfig("lo")
	config.UseXDP = false

	engine, err := NewCaptureEngine(config)
	require.NoError(t, err)
	defer engine.Close()

	stats := engine.GetStats()
	assert.Equal(t, uint64(0), stats.PacketsReceived.Load())
	assert.Equal(t, uint64(0), stats.BytesReceived.Load())
	assert.Equal(t, uint64(0), stats.PacketsDropped.Load())
}

func TestCaptureEngine_GetMode(t *testing.T) {
	config := DefaultCaptureConfig("lo")
	config.UseXDP = false

	engine, err := NewCaptureEngine(config)
	require.NoError(t, err)
	defer engine.Close()

	mode := engine.GetMode()
	assert.Equal(t, CaptureModeStandard, mode)
}

func TestCaptureEngine_IsUsingXDP(t *testing.T) {
	config := DefaultCaptureConfig("lo")
	config.UseXDP = false

	engine, err := NewCaptureEngine(config)
	require.NoError(t, err)
	defer engine.Close()

	assert.False(t, engine.IsUsingXDP())
}

func TestCaptureEngine_XDP_Fallback(t *testing.T) {
	config := DefaultCaptureConfig("nonexistent9999")
	config.UseXDP = true

	engine, err := NewCaptureEngine(config)
	if err != nil {
		// Expected if interface doesn't exist
		t.Skip("Interface does not exist")
	}
	defer engine.Close()

	// Should fall back to standard capture
	assert.Equal(t, CaptureModeStandard, engine.GetMode())
}

func TestCaptureMode_String(t *testing.T) {
	tests := []struct {
		mode     CaptureMode
		expected string
	}{
		{CaptureModeUnknown, "Unknown"},
		{CaptureModeXDP, "AF_XDP"},
		{CaptureModeStandard, "Standard"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.mode.String())
		})
	}
}

func TestCaptureEngine_SwitchMode(t *testing.T) {
	config := DefaultCaptureConfig("lo")
	config.UseXDP = false

	engine, err := NewCaptureEngine(config)
	require.NoError(t, err)
	defer engine.Close()

	initialMode := engine.GetMode()
	assert.Equal(t, CaptureModeStandard, initialMode)

	// Try to switch to XDP (may not work if not supported)
	err = engine.SwitchMode(CaptureModeXDP)
	if err != nil {
		t.Log("XDP mode switch failed (expected if not supported):", err)
	}

	// Try to switch to same mode - should fail
	currentMode := engine.GetMode()
	err = engine.SwitchMode(currentMode)
	assert.Error(t, err)
}

func TestCaptureEngine_Close(t *testing.T) {
	config := DefaultCaptureConfig("lo")
	config.UseXDP = false

	engine, err := NewCaptureEngine(config)
	require.NoError(t, err)

	err = engine.Start()
	assert.NoError(t, err)

	// Close should stop and clean up
	err = engine.Close()
	assert.NoError(t, err)

	// Verify stopped
	assert.False(t, engine.running.Load())
}

func TestCaptureStats_Atomic(t *testing.T) {
	var stats CaptureStats

	// Test atomic operations
	stats.PacketsReceived.Add(100)
	stats.BytesReceived.Add(64000)
	stats.PacketsDropped.Add(5)
	stats.PacketsProcessed.Add(95)
	stats.BatchesProcessed.Add(10)
	stats.Errors.Add(2)

	assert.Equal(t, uint64(100), stats.PacketsReceived.Load())
	assert.Equal(t, uint64(64000), stats.BytesReceived.Load())
	assert.Equal(t, uint64(5), stats.PacketsDropped.Load())
	assert.Equal(t, uint64(95), stats.PacketsProcessed.Load())
	assert.Equal(t, uint64(10), stats.BatchesProcessed.Load())
	assert.Equal(t, uint64(2), stats.Errors.Load())
}

func TestCaptureEngine_StatsReporting(t *testing.T) {
	config := DefaultCaptureConfig("lo")
	config.UseXDP = false
	config.EnableStats = true
	config.StatsInterval = 100 * time.Millisecond

	engine, err := NewCaptureEngine(config)
	require.NoError(t, err)
	defer engine.Close()

	err = engine.Start()
	require.NoError(t, err)

	// Let stats loop run
	time.Sleep(250 * time.Millisecond)

	err = engine.Stop()
	assert.NoError(t, err)
}
