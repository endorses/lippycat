//go:build li

package x1

import (
	"context"
	"encoding/xml"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
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
