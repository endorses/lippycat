//go:build hunter || all

package stats

import (
	"testing"

	"github.com/endorses/lippycat/internal/pkg/sysmetrics"
)

func TestNew_InitializesCPUAsUnavailable(t *testing.T) {
	c := New()
	metrics := c.GetSystemMetrics()
	if metrics.CPUPercent != -1 {
		t.Errorf("Expected initial CPU percent to be -1, got %f", metrics.CPUPercent)
	}
}

func TestNew_InitializesMemoryAsZero(t *testing.T) {
	c := New()
	metrics := c.GetSystemMetrics()
	if metrics.MemoryRSSBytes != 0 {
		t.Errorf("Expected initial memory RSS to be 0, got %d", metrics.MemoryRSSBytes)
	}
	if metrics.MemoryLimitBytes != 0 {
		t.Errorf("Expected initial memory limit to be 0, got %d", metrics.MemoryLimitBytes)
	}
}

func TestIncrementCaptured(t *testing.T) {
	c := New()
	c.IncrementCaptured()
	c.IncrementCaptured()
	c.IncrementCaptured()
	if c.GetCaptured() != 3 {
		t.Errorf("Expected 3 captured, got %d", c.GetCaptured())
	}
}

func TestIncrementMatched(t *testing.T) {
	c := New()
	c.IncrementMatched()
	c.IncrementMatched()
	if c.GetMatched() != 2 {
		t.Errorf("Expected 2 matched, got %d", c.GetMatched())
	}
}

func TestIncrementForwarded(t *testing.T) {
	c := New()
	c.IncrementForwarded(10)
	c.IncrementForwarded(5)
	if c.GetForwarded() != 15 {
		t.Errorf("Expected 15 forwarded, got %d", c.GetForwarded())
	}
}

func TestIncrementDropped(t *testing.T) {
	c := New()
	c.IncrementDropped(3)
	c.IncrementDropped(7)
	if c.GetDropped() != 10 {
		t.Errorf("Expected 10 dropped, got %d", c.GetDropped())
	}
}

func TestSetBufferBytes(t *testing.T) {
	c := New()
	c.SetBufferBytes(1024)
	if c.GetBufferBytes() != 1024 {
		t.Errorf("Expected 1024 buffer bytes, got %d", c.GetBufferBytes())
	}
	c.SetBufferBytes(2048)
	if c.GetBufferBytes() != 2048 {
		t.Errorf("Expected 2048 buffer bytes after update, got %d", c.GetBufferBytes())
	}
}

func TestSetSystemMetrics(t *testing.T) {
	c := New()
	metrics := sysmetrics.Metrics{
		CPUPercent:       45.5,
		MemoryRSSBytes:   104857600,  // 100 MB
		MemoryLimitBytes: 1073741824, // 1 GB
	}
	c.SetSystemMetrics(metrics)

	got := c.GetSystemMetrics()
	if got.CPUPercent != 45.5 {
		t.Errorf("Expected CPU percent 45.5, got %f", got.CPUPercent)
	}
	if got.MemoryRSSBytes != 104857600 {
		t.Errorf("Expected memory RSS 104857600, got %d", got.MemoryRSSBytes)
	}
	if got.MemoryLimitBytes != 1073741824 {
		t.Errorf("Expected memory limit 1073741824, got %d", got.MemoryLimitBytes)
	}
}

func TestSetSystemMetrics_UpdatesExistingValues(t *testing.T) {
	c := New()

	// Set initial values
	c.SetSystemMetrics(sysmetrics.Metrics{
		CPUPercent:       20.0,
		MemoryRSSBytes:   50000000,
		MemoryLimitBytes: 100000000,
	})

	// Update with new values
	c.SetSystemMetrics(sysmetrics.Metrics{
		CPUPercent:       80.0,
		MemoryRSSBytes:   150000000,
		MemoryLimitBytes: 200000000,
	})

	got := c.GetSystemMetrics()
	if got.CPUPercent != 80.0 {
		t.Errorf("Expected updated CPU percent 80.0, got %f", got.CPUPercent)
	}
	if got.MemoryRSSBytes != 150000000 {
		t.Errorf("Expected updated memory RSS 150000000, got %d", got.MemoryRSSBytes)
	}
	if got.MemoryLimitBytes != 200000000 {
		t.Errorf("Expected updated memory limit 200000000, got %d", got.MemoryLimitBytes)
	}
}

func TestGetAll(t *testing.T) {
	c := New()
	c.IncrementCaptured()
	c.IncrementCaptured()
	c.IncrementMatched()
	c.IncrementForwarded(5)
	c.IncrementDropped(2)
	c.SetBufferBytes(512)

	captured, matched, forwarded, dropped, bufferBytes := c.GetAll()

	if captured != 2 {
		t.Errorf("Expected captured 2, got %d", captured)
	}
	if matched != 1 {
		t.Errorf("Expected matched 1, got %d", matched)
	}
	if forwarded != 5 {
		t.Errorf("Expected forwarded 5, got %d", forwarded)
	}
	if dropped != 2 {
		t.Errorf("Expected dropped 2, got %d", dropped)
	}
	if bufferBytes != 512 {
		t.Errorf("Expected bufferBytes 512, got %d", bufferBytes)
	}
}

func TestToProto(t *testing.T) {
	c := New()
	c.IncrementCaptured()
	c.IncrementCaptured()
	c.IncrementCaptured()
	c.IncrementMatched()
	c.IncrementForwarded(10)
	c.IncrementDropped(1)
	c.SetBufferBytes(2048)
	c.SetSystemMetrics(sysmetrics.Metrics{
		CPUPercent:       55.5,
		MemoryRSSBytes:   209715200,  // 200 MB
		MemoryLimitBytes: 4294967296, // 4 GB
	})

	proto := c.ToProto(5)

	if proto.PacketsCaptured != 3 {
		t.Errorf("Expected proto.PacketsCaptured 3, got %d", proto.PacketsCaptured)
	}
	if proto.PacketsMatched != 1 {
		t.Errorf("Expected proto.PacketsMatched 1, got %d", proto.PacketsMatched)
	}
	if proto.PacketsForwarded != 10 {
		t.Errorf("Expected proto.PacketsForwarded 10, got %d", proto.PacketsForwarded)
	}
	if proto.PacketsDropped != 1 {
		t.Errorf("Expected proto.PacketsDropped 1, got %d", proto.PacketsDropped)
	}
	if proto.BufferBytes != 2048 {
		t.Errorf("Expected proto.BufferBytes 2048, got %d", proto.BufferBytes)
	}
	if proto.ActiveFilters != 5 {
		t.Errorf("Expected proto.ActiveFilters 5, got %d", proto.ActiveFilters)
	}
	if proto.CpuPercent != 55.5 {
		t.Errorf("Expected proto.CpuPercent 55.5, got %f", proto.CpuPercent)
	}
	if proto.MemoryRssBytes != 209715200 {
		t.Errorf("Expected proto.MemoryRssBytes 209715200, got %d", proto.MemoryRssBytes)
	}
	if proto.MemoryLimitBytes != 4294967296 {
		t.Errorf("Expected proto.MemoryLimitBytes 4294967296, got %d", proto.MemoryLimitBytes)
	}
}

func TestToProto_WithUnavailableCPU(t *testing.T) {
	c := New()
	// Don't set system metrics - CPU should remain -1

	proto := c.ToProto(0)

	if proto.CpuPercent != -1 {
		t.Errorf("Expected proto.CpuPercent -1 for unavailable CPU, got %f", proto.CpuPercent)
	}
	if proto.MemoryRssBytes != 0 {
		t.Errorf("Expected proto.MemoryRssBytes 0 for unset memory, got %d", proto.MemoryRssBytes)
	}
	if proto.MemoryLimitBytes != 0 {
		t.Errorf("Expected proto.MemoryLimitBytes 0 for unset limit, got %d", proto.MemoryLimitBytes)
	}
}
