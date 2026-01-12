package dns

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/stretchr/testify/assert"
)

func TestNewTunnelingDetector(t *testing.T) {
	config := DefaultTunnelingConfig()
	td := NewTunnelingDetector(config)
	defer td.Stop()

	assert.NotNil(t, td)
	assert.NotNil(t, td.domainStats)
	assert.NotNil(t, td.lastAlerted)
	assert.NotNil(t, td.srcIPs)
}

func TestSetAlertConfig(t *testing.T) {
	td := NewTunnelingDetector(DefaultTunnelingConfig())
	defer td.Stop()

	assert.Nil(t, td.alertConfig)

	alertConfig := AlertConfig{
		Threshold: 0.7,
		Debounce:  5 * time.Minute,
		Callback:  func(alert TunnelingAlert) {},
	}

	td.SetAlertConfig(alertConfig)

	assert.NotNil(t, td.alertConfig)
	assert.Equal(t, 0.7, td.alertConfig.Threshold)
	assert.Equal(t, 5*time.Minute, td.alertConfig.Debounce)
}

func TestAnalyzeWithContext_AlertTriggering(t *testing.T) {
	td := NewTunnelingDetector(DefaultTunnelingConfig())
	defer td.Stop()

	var alertReceived atomic.Bool
	var receivedAlert TunnelingAlert
	var alertMu sync.Mutex

	td.SetAlertConfig(AlertConfig{
		Threshold: 0.3, // Low threshold for testing
		Debounce:  100 * time.Millisecond,
		Callback: func(alert TunnelingAlert) {
			alertMu.Lock()
			receivedAlert = alert
			alertMu.Unlock()
			alertReceived.Store(true)
		},
	})

	// Generate high-entropy queries to trigger tunneling detection
	for i := 0; i < 20; i++ {
		metadata := &types.DNSMetadata{
			QueryName: "aGVsbG93b3JsZHRoaXNpc2F0ZXN0.suspicious.example.com",
			QueryType: "TXT",
		}
		td.AnalyzeWithContext(metadata, "hunter-01", "192.168.1.10")
	}

	// Wait for callback to be called
	time.Sleep(200 * time.Millisecond)

	assert.True(t, alertReceived.Load(), "Alert should have been triggered")

	alertMu.Lock()
	defer alertMu.Unlock()
	assert.Equal(t, "example.com", receivedAlert.Domain)
	assert.Equal(t, "hunter-01", receivedAlert.HunterID)
	assert.Contains(t, receivedAlert.SrcIPs, "192.168.1.10")
	assert.Greater(t, receivedAlert.Score, 0.0)
	assert.Greater(t, receivedAlert.Queries, int64(0))
}

func TestAnalyzeWithContext_Debounce(t *testing.T) {
	td := NewTunnelingDetector(DefaultTunnelingConfig())
	defer td.Stop()

	var alertCount atomic.Int32

	td.SetAlertConfig(AlertConfig{
		Threshold: 0.1, // Very low threshold
		Debounce:  500 * time.Millisecond,
		Callback: func(alert TunnelingAlert) {
			alertCount.Add(1)
		},
	})

	// Generate queries that should trigger alert
	for i := 0; i < 10; i++ {
		metadata := &types.DNSMetadata{
			QueryName: "aGVsbG93b3JsZHRoaXNpc2F0ZXN0.test.example.com",
			QueryType: "TXT",
		}
		td.AnalyzeWithContext(metadata, "hunter-01", "192.168.1.10")
	}

	// Wait for first alert
	time.Sleep(100 * time.Millisecond)
	firstCount := alertCount.Load()

	// Send more queries immediately (should be debounced)
	for i := 0; i < 10; i++ {
		metadata := &types.DNSMetadata{
			QueryName: "bXktb3RoZXItZW5jb2RlZC1kYXRh.test.example.com",
			QueryType: "TXT",
		}
		td.AnalyzeWithContext(metadata, "hunter-01", "192.168.1.10")
	}

	time.Sleep(100 * time.Millisecond)
	secondCount := alertCount.Load()

	// Should still be 1 due to debounce
	assert.Equal(t, firstCount, secondCount, "Alert should be debounced")

	// Wait for debounce to expire
	time.Sleep(600 * time.Millisecond)

	// Send more queries
	for i := 0; i < 10; i++ {
		metadata := &types.DNSMetadata{
			QueryName: "eWV0LWFub3RoZXItZW5jb2RlZC1kYXRh.test.example.com",
			QueryType: "TXT",
		}
		td.AnalyzeWithContext(metadata, "hunter-01", "192.168.1.10")
	}

	time.Sleep(100 * time.Millisecond)
	thirdCount := alertCount.Load()

	// Should now have 2 alerts
	assert.Greater(t, thirdCount, secondCount, "Alert should trigger after debounce expires")
}

func TestAnalyzeWithContext_SourceIPTracking(t *testing.T) {
	td := NewTunnelingDetector(DefaultTunnelingConfig())
	defer td.Stop()

	// First, send queries from all IPs WITHOUT alert config (accumulate IPs)
	srcIPs := []string{"192.168.1.10", "192.168.1.20", "10.0.0.5"}
	for _, srcIP := range srcIPs {
		metadata := &types.DNSMetadata{
			QueryName: "aGVsbG93b3JsZHRoaXNpc2F0ZXN0.multi.example.com",
			QueryType: "TXT",
		}
		td.AnalyzeWithContext(metadata, "hunter-01", srcIP)
	}

	// Now set up alert config and send one more query to trigger the alert
	var receivedAlert TunnelingAlert
	var alertMu sync.Mutex

	td.SetAlertConfig(AlertConfig{
		Threshold: 0.1,
		Debounce:  1 * time.Millisecond,
		Callback: func(alert TunnelingAlert) {
			alertMu.Lock()
			receivedAlert = alert
			alertMu.Unlock()
		},
	})

	// One more query to trigger alert (IPs already accumulated)
	metadata := &types.DNSMetadata{
		QueryName: "bW9yZS1lbmNvZGVkLWRhdGE.multi.example.com",
		QueryType: "TXT",
	}
	td.AnalyzeWithContext(metadata, "hunter-01", "192.168.1.10")

	time.Sleep(100 * time.Millisecond)

	alertMu.Lock()
	defer alertMu.Unlock()

	// All source IPs should be tracked
	assert.Len(t, receivedAlert.SrcIPs, 3, "All source IPs should be tracked")
	for _, expectedIP := range srcIPs {
		assert.Contains(t, receivedAlert.SrcIPs, expectedIP)
	}
}

func TestAnalyzeWithContext_NoAlertBelowThreshold(t *testing.T) {
	td := NewTunnelingDetector(DefaultTunnelingConfig())
	defer td.Stop()

	var alertReceived atomic.Bool

	td.SetAlertConfig(AlertConfig{
		Threshold: 0.99, // Very high threshold
		Debounce:  1 * time.Millisecond,
		Callback: func(alert TunnelingAlert) {
			alertReceived.Store(true)
		},
	})

	// Send a few normal-looking queries
	for i := 0; i < 5; i++ {
		metadata := &types.DNSMetadata{
			QueryName: "www.example.com",
			QueryType: "A",
		}
		td.AnalyzeWithContext(metadata, "hunter-01", "192.168.1.10")
	}

	time.Sleep(100 * time.Millisecond)

	assert.False(t, alertReceived.Load(), "Alert should not trigger below threshold")
}

func TestAnalyzeWithContext_DefaultHunterID(t *testing.T) {
	td := NewTunnelingDetector(DefaultTunnelingConfig())
	defer td.Stop()

	var receivedAlert TunnelingAlert
	var alertMu sync.Mutex

	td.SetAlertConfig(AlertConfig{
		Threshold: 0.1,
		Debounce:  1 * time.Millisecond,
		Callback: func(alert TunnelingAlert) {
			alertMu.Lock()
			receivedAlert = alert
			alertMu.Unlock()
		},
	})

	// Send queries with empty hunter ID
	for i := 0; i < 10; i++ {
		metadata := &types.DNSMetadata{
			QueryName: "aGVsbG93b3JsZHRoaXNpc2F0ZXN0.default.example.com",
			QueryType: "TXT",
		}
		td.AnalyzeWithContext(metadata, "", "192.168.1.10")
	}

	time.Sleep(100 * time.Millisecond)

	alertMu.Lock()
	defer alertMu.Unlock()

	assert.Equal(t, "local", receivedAlert.HunterID, "Empty hunter ID should default to 'local'")
}

func TestAnalyze_BackwardCompatibility(t *testing.T) {
	td := NewTunnelingDetector(DefaultTunnelingConfig())
	defer td.Stop()

	var alertReceived atomic.Bool

	td.SetAlertConfig(AlertConfig{
		Threshold: 0.1,
		Debounce:  1 * time.Millisecond,
		Callback: func(alert TunnelingAlert) {
			alertReceived.Store(true)
			// With backward-compatible Analyze(), hunter should be "local"
			assert.Equal(t, "local", alert.HunterID)
		},
	})

	// Use the old Analyze method (backward compatibility)
	for i := 0; i < 10; i++ {
		metadata := &types.DNSMetadata{
			QueryName: "aGVsbG93b3JsZHRoaXNpc2F0ZXN0.compat.example.com",
			QueryType: "TXT",
		}
		td.Analyze(metadata)
	}

	time.Sleep(100 * time.Millisecond)

	assert.True(t, alertReceived.Load(), "Alert should trigger with backward-compatible Analyze()")
}

func TestCleanup_RemovesAlertTracking(t *testing.T) {
	config := DefaultTunnelingConfig()
	config.MaxAge = 50 * time.Millisecond
	config.CleanupInterval = 100 * time.Millisecond

	td := NewTunnelingDetector(config)
	defer td.Stop()

	// Add some data
	metadata := &types.DNSMetadata{
		QueryName: "test.cleanup.example.com",
		QueryType: "A",
	}
	td.AnalyzeWithContext(metadata, "hunter-01", "192.168.1.10")

	// Verify data exists
	td.mu.RLock()
	assert.Contains(t, td.srcIPs, "example.com")
	td.mu.RUnlock()

	// Wait for cleanup
	time.Sleep(200 * time.Millisecond)

	// Data should be cleaned up
	td.mu.RLock()
	defer td.mu.RUnlock()
	assert.NotContains(t, td.srcIPs, "example.com", "srcIPs should be cleaned up")
	assert.NotContains(t, td.lastAlerted, "example.com", "lastAlerted should be cleaned up")
}

func TestTunnelingAlert_Fields(t *testing.T) {
	alert := TunnelingAlert{
		Domain:    "evil.example.com",
		Score:     0.85,
		Entropy:   4.2,
		Queries:   1523,
		SrcIPs:    []string{"192.168.1.10", "192.168.1.20"},
		HunterID:  "hunter-01",
		Timestamp: time.Now(),
	}

	assert.Equal(t, "evil.example.com", alert.Domain)
	assert.Equal(t, 0.85, alert.Score)
	assert.Equal(t, 4.2, alert.Entropy)
	assert.Equal(t, int64(1523), alert.Queries)
	assert.Len(t, alert.SrcIPs, 2)
	assert.Equal(t, "hunter-01", alert.HunterID)
	assert.False(t, alert.Timestamp.IsZero())
}
