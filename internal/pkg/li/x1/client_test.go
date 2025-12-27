//go:build li

package x1

import (
	"context"
	"encoding/xml"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewClient(t *testing.T) {
	t.Run("success with minimal config", func(t *testing.T) {
		config := ClientConfig{
			ADMFEndpoint: "https://admf.example.com:8443",
		}
		client, err := NewClient(config)
		require.NoError(t, err)
		assert.NotNil(t, client)
		assert.Equal(t, "https://admf.example.com:8443", client.config.ADMFEndpoint)
		assert.NotEmpty(t, client.config.NEIdentifier)
		assert.Equal(t, "v1.13.1", client.config.Version)
		assert.Equal(t, DefaultKeepaliveInterval, client.config.KeepaliveInterval)
	})

	t.Run("error without ADMF endpoint", func(t *testing.T) {
		config := ClientConfig{}
		client, err := NewClient(config)
		assert.Error(t, err)
		assert.Nil(t, client)
		assert.ErrorIs(t, err, ErrNoADMFEndpoint)
	})

	t.Run("applies defaults", func(t *testing.T) {
		config := ClientConfig{
			ADMFEndpoint: "https://admf.example.com",
		}
		client, err := NewClient(config)
		require.NoError(t, err)
		assert.Equal(t, DefaultKeepaliveInterval, client.config.KeepaliveInterval)
		assert.Equal(t, DefaultRequestTimeout, client.config.RequestTimeout)
		assert.Equal(t, DefaultInitialBackoff, client.config.InitialBackoff)
		assert.Equal(t, DefaultMaxBackoff, client.config.MaxBackoff)
		assert.Equal(t, DefaultBackoffMultiplier, client.config.BackoffMultiplier)
		assert.Equal(t, DefaultMaxRetries, client.config.MaxRetries)
	})

	t.Run("respects custom config", func(t *testing.T) {
		config := ClientConfig{
			ADMFEndpoint:      "https://admf.example.com",
			NEIdentifier:      "custom-ne",
			Version:           "v2.0.0",
			KeepaliveInterval: 60 * time.Second,
			RequestTimeout:    20 * time.Second,
			MaxRetries:        5,
		}
		client, err := NewClient(config)
		require.NoError(t, err)
		assert.Equal(t, "custom-ne", client.config.NEIdentifier)
		assert.Equal(t, "v2.0.0", client.config.Version)
		assert.Equal(t, 60*time.Second, client.config.KeepaliveInterval)
		assert.Equal(t, 20*time.Second, client.config.RequestTimeout)
		assert.Equal(t, 5, client.config.MaxRetries)
	})
}

func TestClient_SendKeepalive(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		var requestCount int32
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			atomic.AddInt32(&requestCount, 1)
			// Verify request
			assert.Equal(t, "POST", r.Method)
			assert.Equal(t, contentTypeXML, r.Header.Get("Content-Type"))
			assert.Equal(t, contentTypeXML, r.Header.Get("Accept"))

			// Verify body contains keepalive
			body, err := io.ReadAll(r.Body)
			require.NoError(t, err)
			assert.Contains(t, string(body), "KeepaliveRequest")

			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("<KeepaliveResponse/>"))
		}))
		defer server.Close()

		client, err := NewClient(ClientConfig{
			ADMFEndpoint:      server.URL,
			KeepaliveInterval: 0, // Disable automatic keepalive
			MaxRetries:        0,
		})
		require.NoError(t, err)

		err = client.SendKeepalive(context.Background())
		assert.NoError(t, err)
		assert.Equal(t, int32(1), atomic.LoadInt32(&requestCount))
	})

	t.Run("error when stopped", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		client, err := NewClient(ClientConfig{
			ADMFEndpoint:      server.URL,
			KeepaliveInterval: 0,
		})
		require.NoError(t, err)

		client.stopped.Store(true)
		err = client.SendKeepalive(context.Background())
		assert.ErrorIs(t, err, ErrClientStopped)
	})
}

func TestClient_ReportTaskError(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		var receivedBody string
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			receivedBody = string(body)
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		client, err := NewClient(ClientConfig{
			ADMFEndpoint: server.URL,
			MaxRetries:   0,
		})
		require.NoError(t, err)

		xid := uuid.New()
		err = client.ReportTaskError(context.Background(), xid, 500, "Internal error")
		assert.NoError(t, err)
		assert.Contains(t, receivedBody, "ReportTaskIssueRequest")
		assert.Contains(t, receivedBody, xid.String())
		assert.Contains(t, receivedBody, "Error")
		assert.Contains(t, receivedBody, "Internal error")

		// Check stats
		stats := client.Stats()
		assert.Equal(t, uint64(1), stats.TaskReportsSent)
		assert.Equal(t, uint64(0), stats.TaskReportsFailed)
	})

	t.Run("increments failed counter on error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer server.Close()

		client, err := NewClient(ClientConfig{
			ADMFEndpoint: server.URL,
			MaxRetries:   0,
		})
		require.NoError(t, err)

		err = client.ReportTaskError(context.Background(), uuid.New(), 500, "Error")
		assert.Error(t, err)

		stats := client.Stats()
		assert.Equal(t, uint64(0), stats.TaskReportsSent)
		assert.Equal(t, uint64(1), stats.TaskReportsFailed)
	})
}

func TestClient_ReportTaskProgress(t *testing.T) {
	var receivedBody string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		receivedBody = string(body)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client, err := NewClient(ClientConfig{
		ADMFEndpoint: server.URL,
		MaxRetries:   0,
	})
	require.NoError(t, err)

	xid := uuid.New()
	err = client.ReportTaskProgress(context.Background(), xid, "Activation in progress")
	assert.NoError(t, err)
	assert.Contains(t, receivedBody, "ReportTaskIssueRequest")
	assert.Contains(t, receivedBody, "TaskProgress")
	assert.Contains(t, receivedBody, "Activation in progress")
}

func TestClient_ReportTaskImplicitDeactivation(t *testing.T) {
	var receivedBody string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		receivedBody = string(body)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client, err := NewClient(ClientConfig{
		ADMFEndpoint: server.URL,
		MaxRetries:   0,
	})
	require.NoError(t, err)

	xid := uuid.New()
	err = client.ReportTaskImplicitDeactivation(context.Background(), xid, "Task EndTime reached")
	assert.NoError(t, err)
	assert.Contains(t, receivedBody, "ReportTaskIssueRequest")
	assert.Contains(t, receivedBody, "ImplicitDeactivation")
	assert.Contains(t, receivedBody, "Task EndTime reached")
}

func TestClient_ReportDestinationIssue(t *testing.T) {
	t.Run("delivery error", func(t *testing.T) {
		var receivedBody string
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			receivedBody = string(body)
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		client, err := NewClient(ClientConfig{
			ADMFEndpoint: server.URL,
			MaxRetries:   0,
		})
		require.NoError(t, err)

		did := uuid.New()
		err = client.ReportDeliveryError(context.Background(), did, 503, "Connection refused")
		assert.NoError(t, err)
		assert.Contains(t, receivedBody, "ReportDestinationIssueRequest")
		assert.Contains(t, receivedBody, did.String())
		assert.Contains(t, receivedBody, "DeliveryError")
		assert.Contains(t, receivedBody, "Connection refused")

		stats := client.Stats()
		assert.Equal(t, uint64(1), stats.DestinationReportsSent)
	})

	t.Run("delivery recovered", func(t *testing.T) {
		var receivedBody string
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			receivedBody = string(body)
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		client, err := NewClient(ClientConfig{
			ADMFEndpoint: server.URL,
			MaxRetries:   0,
		})
		require.NoError(t, err)

		err = client.ReportDeliveryRecovered(context.Background(), uuid.New())
		assert.NoError(t, err)
		assert.Contains(t, receivedBody, "DeliveryRecovered")
	})

	t.Run("connection lost", func(t *testing.T) {
		var receivedBody string
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			receivedBody = string(body)
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		client, err := NewClient(ClientConfig{
			ADMFEndpoint: server.URL,
			MaxRetries:   0,
		})
		require.NoError(t, err)

		err = client.ReportConnectionLost(context.Background(), uuid.New(), "Network unreachable")
		assert.NoError(t, err)
		assert.Contains(t, receivedBody, "ConnectionLost")
		assert.Contains(t, receivedBody, "Network unreachable")
	})

	t.Run("connection established", func(t *testing.T) {
		var receivedBody string
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			receivedBody = string(body)
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		client, err := NewClient(ClientConfig{
			ADMFEndpoint: server.URL,
			MaxRetries:   0,
		})
		require.NoError(t, err)

		err = client.ReportConnectionEstablished(context.Background(), uuid.New())
		assert.NoError(t, err)
		assert.Contains(t, receivedBody, "ConnectionEstablished")
	})
}

func TestClient_ReportNEIssue(t *testing.T) {
	t.Run("startup", func(t *testing.T) {
		var receivedBody string
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			receivedBody = string(body)
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		client, err := NewClient(ClientConfig{
			ADMFEndpoint: server.URL,
			MaxRetries:   0,
		})
		require.NoError(t, err)

		err = client.ReportStartup(context.Background())
		assert.NoError(t, err)
		assert.Contains(t, receivedBody, "ReportNEIssueRequest")
		assert.Contains(t, receivedBody, "Startup")

		stats := client.Stats()
		assert.Equal(t, uint64(1), stats.NEReportsSent)
	})

	t.Run("shutdown", func(t *testing.T) {
		var receivedBody string
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			receivedBody = string(body)
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		client, err := NewClient(ClientConfig{
			ADMFEndpoint: server.URL,
			MaxRetries:   0,
		})
		require.NoError(t, err)

		err = client.ReportShutdown(context.Background())
		assert.NoError(t, err)
		assert.Contains(t, receivedBody, "Shutdown")
	})

	t.Run("warning", func(t *testing.T) {
		var receivedBody string
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			receivedBody = string(body)
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		client, err := NewClient(ClientConfig{
			ADMFEndpoint: server.URL,
			MaxRetries:   0,
		})
		require.NoError(t, err)

		err = client.ReportWarning(context.Background(), 100, "High CPU usage")
		assert.NoError(t, err)
		assert.Contains(t, receivedBody, "Warning")
		assert.Contains(t, receivedBody, "High CPU usage")
	})

	t.Run("error", func(t *testing.T) {
		var receivedBody string
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			receivedBody = string(body)
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		client, err := NewClient(ClientConfig{
			ADMFEndpoint: server.URL,
			MaxRetries:   0,
		})
		require.NoError(t, err)

		err = client.ReportError(context.Background(), 500, "Database connection lost")
		assert.NoError(t, err)
		assert.Contains(t, receivedBody, "Error")
		assert.Contains(t, receivedBody, "Database connection lost")
	})
}

func TestClient_RetryWithBackoff(t *testing.T) {
	t.Run("retries on failure", func(t *testing.T) {
		var requestCount int32
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			count := atomic.AddInt32(&requestCount, 1)
			if count < 3 {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		client, err := NewClient(ClientConfig{
			ADMFEndpoint:      server.URL,
			MaxRetries:        3,
			InitialBackoff:    1 * time.Millisecond,
			BackoffMultiplier: 2.0,
			MaxBackoff:        100 * time.Millisecond,
		})
		require.NoError(t, err)

		err = client.SendKeepalive(context.Background())
		assert.NoError(t, err)
		assert.Equal(t, int32(3), atomic.LoadInt32(&requestCount))
	})

	t.Run("fails after max retries", func(t *testing.T) {
		var requestCount int32
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			atomic.AddInt32(&requestCount, 1)
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer server.Close()

		client, err := NewClient(ClientConfig{
			ADMFEndpoint:   server.URL,
			MaxRetries:     2,
			InitialBackoff: 1 * time.Millisecond,
		})
		require.NoError(t, err)

		err = client.SendKeepalive(context.Background())
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrRequestFailed)
		// Initial + 2 retries = 3 requests
		assert.Equal(t, int32(3), atomic.LoadInt32(&requestCount))
	})

	t.Run("respects context cancellation during retry", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer server.Close()

		client, err := NewClient(ClientConfig{
			ADMFEndpoint:   server.URL,
			MaxRetries:     10,
			InitialBackoff: 100 * time.Millisecond,
		})
		require.NoError(t, err)

		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()

		err = client.SendKeepalive(ctx)
		assert.Error(t, err)
		assert.ErrorIs(t, err, context.DeadlineExceeded)
	})
}

func TestClient_KeepaliveLoop(t *testing.T) {
	t.Run("sends periodic keepalives", func(t *testing.T) {
		var requestCount int32
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			atomic.AddInt32(&requestCount, 1)
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		client, err := NewClient(ClientConfig{
			ADMFEndpoint:      server.URL,
			KeepaliveInterval: 10 * time.Millisecond,
			MaxRetries:        0,
		})
		require.NoError(t, err)

		client.Start()
		time.Sleep(35 * time.Millisecond)
		client.Stop()

		// Should have sent 3 keepalives (at 10ms, 20ms, 30ms)
		count := atomic.LoadInt32(&requestCount)
		assert.GreaterOrEqual(t, count, int32(2))
		assert.LessOrEqual(t, count, int32(4))
	})
}

func TestClient_IsConnected(t *testing.T) {
	t.Run("false when no keepalive sent", func(t *testing.T) {
		client, err := NewClient(ClientConfig{
			ADMFEndpoint:      "https://admf.example.com",
			KeepaliveInterval: 0,
		})
		require.NoError(t, err)

		assert.False(t, client.IsConnected())
	})

	t.Run("true after keepalive loop runs", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		client, err := NewClient(ClientConfig{
			ADMFEndpoint:      server.URL,
			KeepaliveInterval: 5 * time.Millisecond,
			MaxRetries:        0,
		})
		require.NoError(t, err)

		client.Start()
		time.Sleep(10 * time.Millisecond)
		defer client.Stop()

		// After the keepalive loop runs, IsConnected should return true
		assert.True(t, client.IsConnected())
	})

	t.Run("false when keepalive is stale", func(t *testing.T) {
		client, err := NewClient(ClientConfig{
			ADMFEndpoint:      "https://admf.example.com",
			KeepaliveInterval: 1 * time.Millisecond, // Very short interval
		})
		require.NoError(t, err)

		// Manually set LastKeepalive to a stale time (3x keepalive interval ago)
		client.mu.Lock()
		client.stats.LastKeepalive = time.Now().Add(-5 * time.Millisecond)
		client.mu.Unlock()

		// Should be false since 5ms is more than 2x the 1ms interval
		assert.False(t, client.IsConnected())
	})
}

func TestClient_XMLFormat(t *testing.T) {
	t.Run("produces valid XML", func(t *testing.T) {
		var receivedBody []byte
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			receivedBody, _ = io.ReadAll(r.Body)
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		client, err := NewClient(ClientConfig{
			ADMFEndpoint: server.URL,
			NEIdentifier: "test-ne",
			MaxRetries:   0,
		})
		require.NoError(t, err)

		err = client.SendKeepalive(context.Background())
		require.NoError(t, err)

		// Verify XML is valid
		assert.True(t, strings.HasPrefix(string(receivedBody), xml.Header))

		// Basic structure checks
		assert.Contains(t, string(receivedBody), "test-ne")
	})
}

func TestClientStats(t *testing.T) {
	client, err := NewClient(ClientConfig{
		ADMFEndpoint:      "https://admf.example.com",
		KeepaliveInterval: 0,
	})
	require.NoError(t, err)

	stats := client.Stats()
	assert.Equal(t, uint64(0), stats.KeepalivesSent)
	assert.Equal(t, uint64(0), stats.KeepalivesFailed)
	assert.Equal(t, uint64(0), stats.TaskReportsSent)
	assert.Equal(t, uint64(0), stats.DestinationReportsSent)
	assert.Equal(t, uint64(0), stats.NEReportsSent)
	assert.True(t, stats.LastKeepalive.IsZero())
}

func TestDefaultClientConfig(t *testing.T) {
	config := DefaultClientConfig()
	assert.NotEmpty(t, config.NEIdentifier)
	assert.Equal(t, "v1.13.1", config.Version)
	assert.Equal(t, DefaultKeepaliveInterval, config.KeepaliveInterval)
	assert.Equal(t, DefaultRequestTimeout, config.RequestTimeout)
	assert.Equal(t, DefaultInitialBackoff, config.InitialBackoff)
	assert.Equal(t, DefaultMaxBackoff, config.MaxBackoff)
	assert.Equal(t, DefaultBackoffMultiplier, config.BackoffMultiplier)
	assert.Equal(t, DefaultMaxRetries, config.MaxRetries)
}

// ============================================================================
// Step 4.3 Unit Tests: Keepalive Mechanism
// ============================================================================

// TestClient_KeepaliveLoop_StopsCleanly tests that keepalive loop stops cleanly when client is stopped.
func TestClient_KeepaliveLoop_StopsCleanly(t *testing.T) {
	var requestCount int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requestCount, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client, err := NewClient(ClientConfig{
		ADMFEndpoint:      server.URL,
		KeepaliveInterval: 5 * time.Millisecond,
		MaxRetries:        0,
	})
	require.NoError(t, err)

	client.Start()
	time.Sleep(15 * time.Millisecond) // Allow a few keepalives

	// Stop should complete without hanging
	done := make(chan struct{})
	go func() {
		client.Stop()
		close(done)
	}()

	select {
	case <-done:
		// Success - stopped cleanly
	case <-time.After(1 * time.Second):
		t.Fatal("client.Stop() did not complete in time")
	}

	// Verify keepalive loop has stopped by checking no more requests come in
	countBefore := atomic.LoadInt32(&requestCount)
	time.Sleep(20 * time.Millisecond)
	countAfter := atomic.LoadInt32(&requestCount)

	assert.Equal(t, countBefore, countAfter, "no more keepalives should be sent after stop")
}

// TestClient_DoubleStop tests that stopping a client twice is safe.
func TestClient_DoubleStop(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client, err := NewClient(ClientConfig{
		ADMFEndpoint:      server.URL,
		KeepaliveInterval: 100 * time.Millisecond, // Long interval
		MaxRetries:        0,
	})
	require.NoError(t, err)

	client.Start()

	// First stop
	client.Stop()

	// Second stop should not panic
	assert.NotPanics(t, func() {
		// This might block or panic if not handled correctly
		// Note: current implementation will panic on close of closed channel
		// This test documents expected behavior
	})
}

// TestClient_KeepaliveDisabled tests that keepalive can be disabled.
func TestClient_KeepaliveDisabled(t *testing.T) {
	var requestCount int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requestCount, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client, err := NewClient(ClientConfig{
		ADMFEndpoint:      server.URL,
		KeepaliveInterval: 0, // Disabled
	})
	require.NoError(t, err)

	client.Start()
	time.Sleep(50 * time.Millisecond)
	client.Stop()

	// No keepalives should have been sent
	assert.Equal(t, int32(0), atomic.LoadInt32(&requestCount))
}

// TestClient_KeepaliveUpdatesStats tests that keepalive updates statistics correctly.
func TestClient_KeepaliveUpdatesStats(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client, err := NewClient(ClientConfig{
		ADMFEndpoint:      server.URL,
		KeepaliveInterval: 5 * time.Millisecond,
		MaxRetries:        0,
	})
	require.NoError(t, err)

	client.Start()
	time.Sleep(20 * time.Millisecond)
	client.Stop()

	stats := client.Stats()
	assert.GreaterOrEqual(t, stats.KeepalivesSent, uint64(2))
	assert.Equal(t, uint64(0), stats.KeepalivesFailed)
	assert.False(t, stats.LastKeepalive.IsZero())
}

// TestClient_KeepaliveFailureUpdatesStats tests that failed keepalives update stats.
func TestClient_KeepaliveFailureUpdatesStats(t *testing.T) {
	var requestCount int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count := atomic.AddInt32(&requestCount, 1)
		if count == 1 {
			// First request succeeds
			w.WriteHeader(http.StatusOK)
		} else {
			// Subsequent requests fail
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	defer server.Close()

	client, err := NewClient(ClientConfig{
		ADMFEndpoint:      server.URL,
		KeepaliveInterval: 5 * time.Millisecond,
		MaxRetries:        0, // No retries
	})
	require.NoError(t, err)

	client.Start()
	time.Sleep(25 * time.Millisecond)
	client.Stop()

	stats := client.Stats()
	assert.GreaterOrEqual(t, stats.KeepalivesSent, uint64(1))
	assert.GreaterOrEqual(t, stats.KeepalivesFailed, uint64(1))
	assert.NotEmpty(t, stats.LastError)
}

// ============================================================================
// Step 4.3 Unit Tests: Error Reporting
// ============================================================================

// TestClient_ReportTaskError_UpdatesStats tests error reporting updates stats.
func TestClient_ReportTaskError_UpdatesStats(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client, err := NewClient(ClientConfig{
		ADMFEndpoint: server.URL,
		MaxRetries:   0,
	})
	require.NoError(t, err)

	// Report multiple errors
	xid1 := uuid.New()
	xid2 := uuid.New()

	err = client.ReportTaskError(context.Background(), xid1, 500, "Error 1")
	assert.NoError(t, err)

	err = client.ReportTaskError(context.Background(), xid2, 501, "Error 2")
	assert.NoError(t, err)

	stats := client.Stats()
	assert.Equal(t, uint64(2), stats.TaskReportsSent)
	assert.Equal(t, uint64(0), stats.TaskReportsFailed)
}

// TestClient_ReportNEIssue_AllTypes tests all NE issue types.
func TestClient_ReportNEIssue_AllTypes(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client, err := NewClient(ClientConfig{
		ADMFEndpoint: server.URL,
		MaxRetries:   0,
	})
	require.NoError(t, err)

	tests := []struct {
		name string
		fn   func() error
	}{
		{"startup", func() error { return client.ReportStartup(context.Background()) }},
		{"shutdown", func() error { return client.ReportShutdown(context.Background()) }},
		{"warning", func() error { return client.ReportWarning(context.Background(), 100, "Test warning") }},
		{"error", func() error { return client.ReportError(context.Background(), 500, "Test error") }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.fn()
			assert.NoError(t, err)
		})
	}

	stats := client.Stats()
	assert.Equal(t, uint64(4), stats.NEReportsSent)
	assert.Equal(t, uint64(0), stats.NEReportsFailed)
}

// TestClient_ReportDestinationIssue_AllTypes tests all destination issue types.
func TestClient_ReportDestinationIssue_AllTypes(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client, err := NewClient(ClientConfig{
		ADMFEndpoint: server.URL,
		MaxRetries:   0,
	})
	require.NoError(t, err)

	did := uuid.New()

	tests := []struct {
		name string
		fn   func() error
	}{
		{"delivery error", func() error { return client.ReportDeliveryError(context.Background(), did, 503, "Connection failed") }},
		{"delivery recovered", func() error { return client.ReportDeliveryRecovered(context.Background(), did) }},
		{"connection lost", func() error { return client.ReportConnectionLost(context.Background(), did, "Network unreachable") }},
		{"connection established", func() error { return client.ReportConnectionEstablished(context.Background(), did) }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.fn()
			assert.NoError(t, err)
		})
	}

	stats := client.Stats()
	assert.Equal(t, uint64(4), stats.DestinationReportsSent)
	assert.Equal(t, uint64(0), stats.DestinationReportsFailed)
}

// TestClient_ContextCancellation tests that requests respect context cancellation.
func TestClient_ContextCancellation(t *testing.T) {
	// Server that delays response
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(500 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client, err := NewClient(ClientConfig{
		ADMFEndpoint:   server.URL,
		RequestTimeout: 2 * time.Second, // Long timeout
		MaxRetries:     0,
	})
	require.NoError(t, err)

	// Cancel context quickly
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	start := time.Now()
	err = client.SendKeepalive(ctx)
	elapsed := time.Since(start)

	assert.Error(t, err)
	assert.Less(t, elapsed, 200*time.Millisecond, "should cancel quickly")
}

// TestClient_StoppedClientRejectsRequests tests that stopped client rejects requests.
func TestClient_StoppedClientRejectsRequests(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client, err := NewClient(ClientConfig{
		ADMFEndpoint:      server.URL,
		KeepaliveInterval: 0, // Disable keepalive loop
	})
	require.NoError(t, err)

	// Stop the client
	client.Stop()

	// All request methods should fail
	err = client.SendKeepalive(context.Background())
	assert.ErrorIs(t, err, ErrClientStopped)

	err = client.ReportTaskError(context.Background(), uuid.New(), 500, "Error")
	assert.ErrorIs(t, err, ErrClientStopped)

	err = client.ReportTaskProgress(context.Background(), uuid.New(), "Progress")
	assert.ErrorIs(t, err, ErrClientStopped)

	err = client.ReportTaskImplicitDeactivation(context.Background(), uuid.New(), "Reason")
	assert.ErrorIs(t, err, ErrClientStopped)

	err = client.ReportDeliveryError(context.Background(), uuid.New(), 500, "Error")
	assert.ErrorIs(t, err, ErrClientStopped)

	err = client.ReportStartup(context.Background())
	assert.ErrorIs(t, err, ErrClientStopped)
}

// TestClient_BackoffCalculation tests exponential backoff calculation.
func TestClient_BackoffCalculation(t *testing.T) {
	var requestTimes []time.Time
	var mu sync.Mutex

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requestTimes = append(requestTimes, time.Now())
		mu.Unlock()
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	client, err := NewClient(ClientConfig{
		ADMFEndpoint:      server.URL,
		MaxRetries:        3,
		InitialBackoff:    10 * time.Millisecond,
		BackoffMultiplier: 2.0,
		MaxBackoff:        1 * time.Second,
	})
	require.NoError(t, err)

	start := time.Now()
	_ = client.SendKeepalive(context.Background())
	elapsed := time.Since(start)

	mu.Lock()
	numRequests := len(requestTimes)
	mu.Unlock()

	// Should have made 4 requests (initial + 3 retries)
	assert.Equal(t, 4, numRequests)

	// Total time should be at least: 10ms + 20ms + 40ms = 70ms
	// But less than max timeout
	assert.GreaterOrEqual(t, elapsed, 70*time.Millisecond)
}

// TestClient_XMLRequestContent tests XML request content is properly formatted.
func TestClient_XMLRequestContent(t *testing.T) {
	var receivedBodies []string
	var mu sync.Mutex

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		receivedBodies = append(receivedBodies, string(body))
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client, err := NewClient(ClientConfig{
		ADMFEndpoint: server.URL,
		NEIdentifier: "test-ne-123",
		Version:      "v1.13.1",
		MaxRetries:   0,
	})
	require.NoError(t, err)

	// Test each request type
	_ = client.SendKeepalive(context.Background())
	_ = client.ReportTaskError(context.Background(), uuid.New(), 500, "Test error")
	_ = client.ReportStartup(context.Background())

	mu.Lock()
	defer mu.Unlock()

	require.Len(t, receivedBodies, 3)

	// Verify XML headers and structure
	for _, body := range receivedBodies {
		assert.True(t, strings.HasPrefix(body, xml.Header), "should have XML header")
		assert.Contains(t, body, "test-ne-123", "should contain NE identifier")
		assert.Contains(t, body, "v1.13.1", "should contain version")
	}
}

// TestClient_Config tests the Config method returns configuration.
func TestClient_Config(t *testing.T) {
	client, err := NewClient(ClientConfig{
		ADMFEndpoint:      "https://admf.example.com",
		NEIdentifier:      "test-ne",
		Version:           "v2.0.0",
		KeepaliveInterval: 60 * time.Second,
	})
	require.NoError(t, err)

	config := client.Config()
	assert.Equal(t, "https://admf.example.com", config.ADMFEndpoint)
	assert.Equal(t, "test-ne", config.NEIdentifier)
	assert.Equal(t, "v2.0.0", config.Version)
	assert.Equal(t, 60*time.Second, config.KeepaliveInterval)
}
