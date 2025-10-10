package voip

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDefaultXDPConfig(t *testing.T) {
	config := DefaultXDPConfig("eth0")

	assert.Equal(t, "eth0", config.Interface)
	assert.Equal(t, 0, config.QueueID)
	assert.Equal(t, 4*1024*1024, config.UMEMSize)
	assert.Equal(t, 4096, config.NumFrames)
	assert.Equal(t, 2048, config.FrameSize)
	assert.True(t, config.EnableStats)
	assert.Equal(t, 64, config.BatchSize)
}

func TestIsXDPSupported(t *testing.T) {
	// This test just checks if the function runs without panic
	supported := IsXDPSupported()

	t.Logf("XDP Supported: %v", supported)

	// We can't assert true/false as it depends on the system
	// But we can verify it returns a boolean
	assert.IsType(t, false, supported)
}

func TestUMEMAllocation(t *testing.T) {
	// Test UMEM frame management
	size := 1024 * 1024 // 1MB
	frameSize := 2048
	numFrames := size / frameSize

	umem, err := newUMEM(size, frameSize, numFrames)
	if err != nil {
		t.Skip("UMEM allocation not available on this system")
		return
	}
	defer func() {
		if umem.area != nil {
			// Cleanup handled by Close()
		}
	}()

	assert.NotNil(t, umem)
	assert.Equal(t, size, umem.size)
	assert.Equal(t, frameSize, umem.frameSize)
	assert.Equal(t, numFrames, umem.numFrames)
	assert.Equal(t, numFrames, len(umem.freeStack))

	// Test frame allocation
	idx, ok := umem.AllocFrame()
	assert.True(t, ok)
	assert.Less(t, idx, uint64(numFrames))

	// Test frame retrieval
	frameData := umem.GetFrame(idx)
	assert.NotNil(t, frameData)
	assert.Equal(t, frameSize, len(frameData))

	// Test frame free
	umem.FreeFrame(idx)
	assert.Equal(t, numFrames, len(umem.freeStack))
}

func TestUMEMExhaustion(t *testing.T) {
	size := 8192 // Small size
	frameSize := 2048
	numFrames := 4

	umem, err := newUMEM(size, frameSize, numFrames)
	if err != nil {
		t.Skip("UMEM allocation not available")
		return
	}

	// Allocate all frames
	allocated := make([]uint64, 0, numFrames)
	for i := 0; i < numFrames; i++ {
		idx, ok := umem.AllocFrame()
		assert.True(t, ok, "Frame %d should allocate", i)
		allocated = append(allocated, idx)
	}

	// Try to allocate one more - should fail
	_, ok := umem.AllocFrame()
	assert.False(t, ok, "Should fail when UMEM exhausted")

	// Free all frames
	for _, idx := range allocated {
		umem.FreeFrame(idx)
	}

	// Should be able to allocate again
	idx, ok := umem.AllocFrame()
	assert.True(t, ok)
	assert.NotNil(t, idx)
}

func TestXDPSocketCreation_NoInterface(t *testing.T) {
	config := DefaultXDPConfig("nonexistent9999")

	socket, err := NewXDPSocket(config)
	if err == nil {
		socket.Close()
		t.Skip("XDP socket creation succeeded unexpectedly")
	}

	// We expect an error for nonexistent interface
	assert.Error(t, err)
	assert.Nil(t, socket)
}

func TestXDPStats(t *testing.T) {
	var stats XDPStats

	// Test atomic operations
	stats.RxPackets.Add(100)
	stats.RxBytes.Add(64000)
	stats.TxPackets.Add(50)
	stats.TxBytes.Add(32000)
	stats.RxDropped.Add(5)

	assert.Equal(t, uint64(100), stats.RxPackets.Load())
	assert.Equal(t, uint64(64000), stats.RxBytes.Load())
	assert.Equal(t, uint64(50), stats.TxPackets.Load())
	assert.Equal(t, uint64(32000), stats.TxBytes.Load())
	assert.Equal(t, uint64(5), stats.RxDropped.Load())

	// Test String() formatting
	str := stats.String()
	assert.Contains(t, str, "100 pkts")
	assert.Contains(t, str, "64000 bytes")
	assert.Contains(t, str, "Dropped: 5")
}

func TestXDPConfig_Validation(t *testing.T) {
	tests := []struct {
		name    string
		config  *XDPConfig
		wantErr bool
	}{
		{
			name:    "nil config",
			config:  nil,
			wantErr: true,
		},
		{
			name:    "valid config",
			config:  DefaultXDPConfig("eth0"),
			wantErr: false, // May still fail if XDP not supported
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			socket, err := NewXDPSocket(tt.config)
			if socket != nil {
				defer socket.Close()
			}

			if tt.wantErr {
				assert.Error(t, err)
			}
			// Note: We don't assert no error for valid config
			// because XDP may not be available on test system
		})
	}
}

func TestGetInterfaceIndex(t *testing.T) {
	// Test with loopback interface (should exist on all systems)
	idx, err := getInterfaceIndex("lo")
	if err != nil {
		t.Skip("Could not get loopback interface index")
	}

	assert.NoError(t, err)
	assert.Greater(t, idx, 0)
	t.Logf("Loopback interface index: %d", idx)

	// Test with nonexistent interface
	_, err = getInterfaceIndex("nonexistent9999")
	assert.Error(t, err)
}

func TestXDPSocket_ClosedState(t *testing.T) {
	// Create a mock XDPSocket
	socket := &XDPSocket{
		fd: -1,
	}
	socket.closed.Store(false)

	// Close it
	err := socket.Close()
	assert.NoError(t, err)

	// Try to close again
	err = socket.Close()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "already closed")

	// Try to receive after close
	_, err = socket.ReceiveBatch(10)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "socket closed")
}

func BenchmarkUMEMAllocation(b *testing.B) {
	size := 4 * 1024 * 1024
	frameSize := 2048
	numFrames := size / frameSize

	umem, err := newUMEM(size, frameSize, numFrames)
	if err != nil {
		b.Skip("UMEM allocation not available")
		return
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		idx, ok := umem.AllocFrame()
		if !ok {
			// UMEM exhausted, free all and continue
			for j := 0; j < numFrames; j++ {
				umem.FreeFrame(uint64(j))
			}
			idx, _ = umem.AllocFrame()
		}
		umem.FreeFrame(idx)
	}
}

func BenchmarkXDPStats(b *testing.B) {
	var stats XDPStats

	b.ResetTimer()
	b.ReportAllocs()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			stats.RxPackets.Add(1)
			stats.RxBytes.Add(1500)
			_ = stats.RxPackets.Load()
		}
	})
}
