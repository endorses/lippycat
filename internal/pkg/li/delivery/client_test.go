//go:build li

package delivery

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/endorses/lippycat/internal/pkg/li"
)

// testCertDir returns the path to the LI test certificates directory.
func testCertDir() string {
	return filepath.Join("..", "..", "..", "..", "test", "testcerts", "li")
}

// testConfigWithCerts returns a DestinationConfig with test TLS certificates.
// If certificates are not available, the test is skipped.
func testConfigWithCerts(t *testing.T) DestinationConfig {
	t.Helper()
	certDir := testCertDir()
	certPath := filepath.Join(certDir, "delivery-client-cert.pem")
	keyPath := filepath.Join(certDir, "delivery-client-key.pem")
	caPath := filepath.Join(certDir, "ca-cert.pem")

	// Check if certificates exist.
	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		t.Skip("LI test certificates not available - run test/testcerts/generate_li_test_certs.sh first")
	}

	config := DefaultConfig()
	config.TLSCertFile = certPath
	config.TLSKeyFile = keyPath
	config.TLSCAFile = caPath
	return config
}

func TestNewClient(t *testing.T) {
	manager, err := NewManager(testConfigWithCerts(t))
	require.NoError(t, err)
	defer manager.Stop()

	client := NewClient(manager, DefaultClientConfig())
	assert.NotNil(t, client)
	assert.Equal(t, DefaultQueueSize, client.config.QueueSize)
	assert.Equal(t, DefaultWorkers, client.config.Workers)
}

func TestDefaultClientConfig(t *testing.T) {
	config := DefaultClientConfig()

	assert.Equal(t, DefaultQueueSize, config.QueueSize)
	assert.Equal(t, DefaultWorkers, config.Workers)
	assert.Equal(t, DefaultBatchSize, config.BatchSize)
	assert.Equal(t, DefaultBatchTimeout, config.BatchTimeout)
	assert.Equal(t, DefaultSendTimeout, config.SendTimeout)
	assert.Equal(t, DefaultShutdownTimeout, config.ShutdownTimeout)
}

func TestClientConfigDefaults(t *testing.T) {
	manager, err := NewManager(testConfigWithCerts(t))
	require.NoError(t, err)
	defer manager.Stop()

	// Test with zero values - should use defaults.
	client := NewClient(manager, ClientConfig{})
	assert.Equal(t, DefaultQueueSize, client.config.QueueSize)
	assert.Equal(t, DefaultWorkers, client.config.Workers)
	assert.Equal(t, DefaultBatchSize, client.config.BatchSize)
	assert.Equal(t, DefaultBatchTimeout, client.config.BatchTimeout)
	assert.Equal(t, DefaultSendTimeout, client.config.SendTimeout)
	assert.Equal(t, DefaultShutdownTimeout, client.config.ShutdownTimeout)
}

func TestSendX2QueueFull(t *testing.T) {
	manager, err := NewManager(testConfigWithCerts(t))
	require.NoError(t, err)
	defer manager.Stop()

	config := DefaultClientConfig()
	config.QueueSize = 1
	config.Workers = 0 // No workers to process queue.

	client := NewClient(manager, config)
	// Don't start workers - let queue fill up.

	xid := uuid.New()
	destIDs := []uuid.UUID{uuid.New()}
	data := []byte("test-pdu")

	// First should succeed.
	err = client.SendX2(xid, destIDs, data)
	require.NoError(t, err)

	// Second is accepted and evicts the oldest queued item.
	err = client.SendX2(xid, destIDs, data)
	require.NoError(t, err)

	stats := client.Stats()
	assert.Equal(t, uint64(2), stats.X2Queued)
	assert.Equal(t, uint64(1), stats.X2Dropped)
	assert.Equal(t, int64(1), stats.QueueDepth)
}

func TestSendX3QueueFull(t *testing.T) {
	manager, err := NewManager(testConfigWithCerts(t))
	require.NoError(t, err)
	defer manager.Stop()

	config := DefaultClientConfig()
	config.QueueSize = 1
	config.Workers = 0

	client := NewClient(manager, config)

	xid := uuid.New()
	destIDs := []uuid.UUID{uuid.New()}
	data := []byte("test-pdu")

	err = client.SendX3(xid, destIDs, data)
	require.NoError(t, err)

	err = client.SendX3(xid, destIDs, data)
	require.NoError(t, err)

	stats := client.Stats()
	assert.Equal(t, uint64(2), stats.X3Queued)
	assert.Equal(t, uint64(1), stats.X3Dropped)
	assert.Equal(t, int64(1), stats.QueueDepth)
}

func TestPerDestinationQueueIsolation(t *testing.T) {
	manager, err := NewManager(testConfigWithCerts(t))
	require.NoError(t, err)
	defer manager.Stop()

	config := DefaultClientConfig()
	config.QueueSize = 1
	client := NewClient(manager, config)

	did1 := uuid.New()
	did2 := uuid.New()
	xid := uuid.New()

	require.NoError(t, client.SendX2(xid, []uuid.UUID{did1}, []byte("old1")))
	require.NoError(t, client.SendX2(xid, []uuid.UUID{did2}, []byte("keep")))
	require.NoError(t, client.SendX2(xid, []uuid.UUID{did1}, []byte("new1")))

	stats := client.DestinationStats()
	assert.Equal(t, 1, stats[did1].QueueDepth)
	assert.Equal(t, uint64(1), stats[did1].QueueOverflows)
	assert.Equal(t, uint64(1), stats[did1].DroppedByReason["queue_overflow"])
	assert.Equal(t, uint64(1), stats[did1].X2Dropped)
	assert.Equal(t, 1, stats[did2].QueueDepth)
	assert.Equal(t, uint64(0), stats[did2].QueueOverflows)
	assert.Equal(t, int64(2), client.Stats().QueueDepth)
}

func TestProtocolTypeAwareFanout(t *testing.T) {
	tests := []struct {
		name     string
		send     func(*Client, uuid.UUID, []uuid.UUID, []byte) error
		expected []string
	}{
		{
			name: "X2",
			send: (*Client).SendX2,
			expected: []string{
				"X2",
				"X2andX3",
			},
		},
		{
			name: "X3",
			send: (*Client).SendX3,
			expected: []string{
				"X3",
				"X2andX3",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manager, err := NewManager(testConfigWithCerts(t))
			require.NoError(t, err)
			defer manager.Stop()

			client := NewClient(manager, DefaultClientConfig())
			destIDs := make([]uuid.UUID, 0, 4)
			didsByProtocol := make(map[string]uuid.UUID, 4)
			for i, protocolType := range []string{"X2", "X3", "X2andX3", "HI3"} {
				did := uuid.New()
				destIDs = append(destIDs, did)
				didsByProtocol[protocolType] = did
				require.NoError(t, manager.AddDestination(&li.Destination{
					DID:          did,
					Address:      "127.0.0.1",
					Port:         20000 + i,
					ProtocolType: protocolType,
				}))
			}

			require.NoError(t, tt.send(client, uuid.New(), destIDs, []byte("test-pdu")))

			stats := client.DestinationStats()
			expected := make(map[string]bool, len(tt.expected))
			for _, protocolType := range tt.expected {
				expected[protocolType] = true
			}
			for protocolType, did := range didsByProtocol {
				_, queued := stats[did]
				assert.Equal(t, expected[protocolType], queued, protocolType)
			}
			assert.Equal(t, int64(len(tt.expected)), client.Stats().QueueDepth)
		})
	}
}

func TestProtocolTypeFanoutBackwardCompatibility(t *testing.T) {
	tests := []struct {
		name         string
		protocolType string
	}{
		{name: "empty"},
		{name: "unknown", protocolType: "future-protocol"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manager, err := NewManager(testConfigWithCerts(t))
			require.NoError(t, err)
			defer manager.Stop()

			did := uuid.New()
			require.NoError(t, manager.AddDestination(&li.Destination{
				DID:          did,
				Address:      "127.0.0.1",
				Port:         21000,
				ProtocolType: tt.protocolType,
			}))

			client := NewClient(manager, DefaultClientConfig())
			require.NoError(t, client.SendX2(uuid.New(), []uuid.UUID{did}, []byte("x2")))
			require.NoError(t, client.SendX3(uuid.New(), []uuid.UUID{did}, []byte("x3")))

			stats := client.DestinationStats()
			assert.Equal(t, 2, stats[did].QueueDepth)
			assert.Equal(t, int64(2), client.Stats().QueueDepth)
		})
	}
}

func TestProtocolTypeFanoutPreservesRedundantDestinations(t *testing.T) {
	manager, err := NewManager(testConfigWithCerts(t))
	require.NoError(t, err)
	defer manager.Stop()

	destIDs := []uuid.UUID{uuid.New(), uuid.New()}
	for _, did := range destIDs {
		require.NoError(t, manager.AddDestination(&li.Destination{
			DID:          did,
			Address:      "mdf.example.com",
			Port:         9443,
			ProtocolType: "X3",
		}))
	}

	client := NewClient(manager, DefaultClientConfig())
	require.NoError(t, client.SendX3(uuid.New(), destIDs, []byte("x3")))

	stats := client.DestinationStats()
	assert.Equal(t, 1, stats[destIDs[0]].QueueDepth)
	assert.Equal(t, 1, stats[destIDs[1]].QueueDepth)
	assert.Equal(t, int64(2), client.Stats().QueueDepth)
}

func TestSendNoDestinations(t *testing.T) {
	manager, err := NewManager(testConfigWithCerts(t))
	require.NoError(t, err)
	defer manager.Stop()

	client := NewClient(manager, DefaultClientConfig())

	xid := uuid.New()
	data := []byte("test-pdu")

	err = client.SendX2(xid, nil, data)
	assert.ErrorIs(t, err, ErrNoDestinations)

	err = client.SendX2(xid, []uuid.UUID{}, data)
	assert.ErrorIs(t, err, ErrNoDestinations)

	err = client.SendX3(xid, nil, data)
	assert.ErrorIs(t, err, ErrNoDestinations)
}

func TestSendAfterStop(t *testing.T) {
	manager, err := NewManager(testConfigWithCerts(t))
	require.NoError(t, err)
	defer manager.Stop()

	client := NewClient(manager, DefaultClientConfig())
	client.Start()
	client.Stop()

	xid := uuid.New()
	destIDs := []uuid.UUID{uuid.New()}
	data := []byte("test-pdu")

	err = client.SendX2(xid, destIDs, data)
	assert.ErrorIs(t, err, ErrClientStopped)

	err = client.SendX3(xid, destIDs, data)
	assert.ErrorIs(t, err, ErrClientStopped)
}

func TestSequenceNumbering(t *testing.T) {
	manager, err := NewManager(testConfigWithCerts(t))
	require.NoError(t, err)
	defer manager.Stop()

	client := NewClient(manager, DefaultClientConfig())

	xid1 := uuid.New()
	xid2 := uuid.New()
	did1 := uuid.New()
	did2 := uuid.New()

	// First sequence for xid1+did1 should be 1.
	seq := client.NextSequence(xid1, did1)
	assert.Equal(t, uint32(1), seq)

	// Next should be 2.
	seq = client.NextSequence(xid1, did1)
	assert.Equal(t, uint32(2), seq)

	// Different destination, same xid - new sequence.
	seq = client.NextSequence(xid1, did2)
	assert.Equal(t, uint32(1), seq)

	// Different xid, same destination - new sequence.
	seq = client.NextSequence(xid2, did1)
	assert.Equal(t, uint32(1), seq)

	// Original stream continues.
	seq = client.NextSequence(xid1, did1)
	assert.Equal(t, uint32(3), seq)
}

func TestSequenceNumberingConcurrent(t *testing.T) {
	manager, err := NewManager(testConfigWithCerts(t))
	require.NoError(t, err)
	defer manager.Stop()

	client := NewClient(manager, DefaultClientConfig())

	xid := uuid.New()
	did := uuid.New()

	var wg sync.WaitGroup
	seqs := make([]uint32, 100)

	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			seqs[idx] = client.NextSequence(xid, did)
		}(i)
	}

	wg.Wait()

	// All sequences should be unique (1-100).
	seen := make(map[uint32]bool)
	for _, seq := range seqs {
		assert.False(t, seen[seq], "duplicate sequence: %d", seq)
		seen[seq] = true
	}
	assert.Len(t, seen, 100)
}

func TestResetSequence(t *testing.T) {
	manager, err := NewManager(testConfigWithCerts(t))
	require.NoError(t, err)
	defer manager.Stop()

	client := NewClient(manager, DefaultClientConfig())

	xid1 := uuid.New()
	xid2 := uuid.New()
	did := uuid.New()

	// Generate some sequences.
	_ = client.NextSequence(xid1, did)
	_ = client.NextSequence(xid1, did)
	_ = client.NextSequence(xid2, did)

	// Reset xid1.
	client.ResetSequence(xid1)

	// xid1 should restart from 1.
	seq := client.NextSequence(xid1, did)
	assert.Equal(t, uint32(1), seq)

	// xid2 should continue.
	seq = client.NextSequence(xid2, did)
	assert.Equal(t, uint32(2), seq)
}

func TestQueueDepth(t *testing.T) {
	manager, err := NewManager(testConfigWithCerts(t))
	require.NoError(t, err)
	defer manager.Stop()

	config := DefaultClientConfig()
	config.QueueSize = 100
	config.Workers = 0 // Don't process.

	client := NewClient(manager, config)

	assert.Equal(t, 0, client.QueueDepth())

	xid := uuid.New()
	destIDs := []uuid.UUID{uuid.New()}

	// Queue some items.
	for i := 0; i < 10; i++ {
		err := client.SendX2(xid, destIDs, []byte("test"))
		require.NoError(t, err)
	}

	assert.Equal(t, 10, client.QueueDepth())

	stats := client.Stats()
	assert.Equal(t, int64(10), stats.QueueDepth)
}

func TestClientStartStop(t *testing.T) {
	manager, err := NewManager(testConfigWithCerts(t))
	require.NoError(t, err)
	defer manager.Stop()

	client := NewClient(manager, DefaultClientConfig())

	// Start and stop should not panic.
	client.Start()
	client.Stop()
}

func TestDeliveryToConnectedDestination(t *testing.T) {
	certPEM, keyPEM := generateTestCert(t)

	listener, port := startTestTLSServer(t, certPEM, keyPEM)
	defer listener.Close()

	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM(certPEM)

	managerConfig := testConfigWithCerts(t)
	managerConfig.DialTimeout = 2 * time.Second

	manager, err := NewManager(managerConfig)
	require.NoError(t, err)
	defer manager.Stop()

	did := uuid.New()
	dest := &li.Destination{
		DID:       did,
		Address:   "127.0.0.1",
		Port:      port,
		X2Enabled: true,
		X3Enabled: true,
		TLSConfig: &tls.Config{
			RootCAs:            certPool,
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
		},
	}

	err = manager.AddDestination(dest)
	require.NoError(t, err)

	// Wait for connection.
	time.Sleep(500 * time.Millisecond)
	require.True(t, manager.IsConnected(did))

	clientConfig := DefaultClientConfig()
	clientConfig.BatchSize = 1 // Send immediately.
	clientConfig.BatchTimeout = 10 * time.Millisecond

	client := NewClient(manager, clientConfig)
	client.Start()
	defer client.Stop()

	xid := uuid.New()

	// Send X2.
	err = client.SendX2(xid, []uuid.UUID{did}, []byte("test-x2-pdu"))
	require.NoError(t, err)

	// Send X3.
	err = client.SendX3(xid, []uuid.UUID{did}, []byte("test-x3-pdu"))
	require.NoError(t, err)

	// Wait for delivery.
	time.Sleep(100 * time.Millisecond)

	stats := client.Stats()
	assert.Equal(t, uint64(1), stats.X2Queued)
	assert.Equal(t, uint64(1), stats.X3Queued)
	assert.Equal(t, uint64(1), stats.X2Sent)
	assert.Equal(t, uint64(1), stats.X3Sent)
}

func TestDeliveryToMultipleDestinations(t *testing.T) {
	certPEM, keyPEM := generateTestCert(t)

	listener1, port1 := startTestTLSServer(t, certPEM, keyPEM)
	defer listener1.Close()

	listener2, port2 := startTestTLSServer(t, certPEM, keyPEM)
	defer listener2.Close()

	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM(certPEM)

	tlsConfig := &tls.Config{
		RootCAs:            certPool,
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
	}

	managerConfig := testConfigWithCerts(t)
	managerConfig.DialTimeout = 2 * time.Second

	manager, err := NewManager(managerConfig)
	require.NoError(t, err)
	defer manager.Stop()

	did1 := uuid.New()
	did2 := uuid.New()

	err = manager.AddDestination(&li.Destination{
		DID:       did1,
		Address:   "127.0.0.1",
		Port:      port1,
		X2Enabled: true,
		TLSConfig: tlsConfig.Clone(),
	})
	require.NoError(t, err)

	err = manager.AddDestination(&li.Destination{
		DID:       did2,
		Address:   "127.0.0.1",
		Port:      port2,
		X2Enabled: true,
		TLSConfig: tlsConfig.Clone(),
	})
	require.NoError(t, err)

	// Wait for connections.
	time.Sleep(500 * time.Millisecond)

	clientConfig := DefaultClientConfig()
	clientConfig.BatchSize = 1
	clientConfig.BatchTimeout = 10 * time.Millisecond
	clientConfig.ShutdownTimeout = 10 * time.Millisecond

	client := NewClient(manager, clientConfig)
	client.Start()
	defer client.Stop()

	xid := uuid.New()

	// Send to both destinations.
	err = client.SendX2(xid, []uuid.UUID{did1, did2}, []byte("test-pdu"))
	require.NoError(t, err)

	// Wait for delivery.
	time.Sleep(100 * time.Millisecond)

	stats := client.Stats()
	assert.Equal(t, uint64(1), stats.X2Queued)
	// Should be sent to both destinations.
	assert.Equal(t, uint64(2), stats.X2Sent)
}

func TestDeliveryFailure(t *testing.T) {
	manager, err := NewManager(testConfigWithCerts(t))
	require.NoError(t, err)
	defer manager.Stop()

	did := uuid.New()
	err = manager.AddDestination(&li.Destination{
		DID:     did,
		Address: "127.0.0.1",
		Port:    1, // Unavailable.
	})
	require.NoError(t, err)

	clientConfig := DefaultClientConfig()
	clientConfig.BatchSize = 1
	clientConfig.BatchTimeout = 10 * time.Millisecond
	clientConfig.ShutdownTimeout = 10 * time.Millisecond

	client := NewClient(manager, clientConfig)
	client.Start()
	defer client.Stop()

	xid := uuid.New()

	err = client.SendX2(xid, []uuid.UUID{did}, []byte("test-pdu"))
	require.NoError(t, err)

	// Wait for delivery attempt.
	time.Sleep(200 * time.Millisecond)

	stats := client.Stats()
	assert.Equal(t, uint64(1), stats.X2Queued)
	assert.Equal(t, uint64(0), stats.X2Failed)
	assert.Equal(t, uint64(0), stats.X2Sent)
	assert.Equal(t, int64(1), stats.QueueDepth)
	assert.Greater(t, stats.Retries, uint64(0))
}

func TestSendX2Sync(t *testing.T) {
	certPEM, keyPEM := generateTestCert(t)

	listener, port := startTestTLSServer(t, certPEM, keyPEM)
	defer listener.Close()

	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM(certPEM)

	managerConfig := testConfigWithCerts(t)
	manager, err := NewManager(managerConfig)
	require.NoError(t, err)
	defer manager.Stop()

	did := uuid.New()
	err = manager.AddDestination(&li.Destination{
		DID:       did,
		Address:   "127.0.0.1",
		Port:      port,
		X2Enabled: true,
		TLSConfig: &tls.Config{
			RootCAs:            certPool,
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
		},
	})
	require.NoError(t, err)

	// Wait for connection.
	time.Sleep(500 * time.Millisecond)

	client := NewClient(manager, DefaultClientConfig())
	client.Start()
	defer client.Stop()

	ctx := context.Background()
	xid := uuid.New()

	err = client.SendX2Sync(ctx, xid, []uuid.UUID{did}, []byte("test-pdu"))
	assert.NoError(t, err)

	stats := client.Stats()
	assert.Equal(t, uint64(1), stats.X2Sent)
}

func TestSendX3Sync(t *testing.T) {
	certPEM, keyPEM := generateTestCert(t)

	listener, port := startTestTLSServer(t, certPEM, keyPEM)
	defer listener.Close()

	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM(certPEM)

	managerConfig := testConfigWithCerts(t)
	manager, err := NewManager(managerConfig)
	require.NoError(t, err)
	defer manager.Stop()

	did := uuid.New()
	err = manager.AddDestination(&li.Destination{
		DID:       did,
		Address:   "127.0.0.1",
		Port:      port,
		X3Enabled: true,
		TLSConfig: &tls.Config{
			RootCAs:            certPool,
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
		},
	})
	require.NoError(t, err)

	time.Sleep(500 * time.Millisecond)

	client := NewClient(manager, DefaultClientConfig())
	client.Start()
	defer client.Stop()

	ctx := context.Background()
	xid := uuid.New()

	err = client.SendX3Sync(ctx, xid, []uuid.UUID{did}, []byte("test-pdu"))
	assert.NoError(t, err)

	stats := client.Stats()
	assert.Equal(t, uint64(1), stats.X3Sent)
}

func TestSendSyncAllFailed(t *testing.T) {
	manager, err := NewManager(testConfigWithCerts(t))
	require.NoError(t, err)
	defer manager.Stop()

	did := uuid.New()
	err = manager.AddDestination(&li.Destination{
		DID:     did,
		Address: "127.0.0.1",
		Port:    1,
	})
	require.NoError(t, err)

	client := NewClient(manager, DefaultClientConfig())
	client.Start()
	defer client.Stop()

	ctx := context.Background()
	xid := uuid.New()

	err = client.SendX2Sync(ctx, xid, []uuid.UUID{did}, []byte("test-pdu"))
	assert.ErrorIs(t, err, ErrAllDeliveriesFailed)
}

func TestSendSyncContextCanceled(t *testing.T) {
	manager, err := NewManager(testConfigWithCerts(t))
	require.NoError(t, err)
	defer manager.Stop()

	client := NewClient(manager, DefaultClientConfig())
	client.Start()
	defer client.Stop()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately.

	xid := uuid.New()
	destIDs := []uuid.UUID{uuid.New(), uuid.New()}

	err = client.SendX2Sync(ctx, xid, destIDs, []byte("test-pdu"))
	assert.ErrorIs(t, err, context.Canceled)
}

func TestSendSyncAfterStop(t *testing.T) {
	manager, err := NewManager(testConfigWithCerts(t))
	require.NoError(t, err)
	defer manager.Stop()

	client := NewClient(manager, DefaultClientConfig())
	client.Start()
	client.Stop()

	ctx := context.Background()
	xid := uuid.New()
	destIDs := []uuid.UUID{uuid.New()}

	err = client.SendX2Sync(ctx, xid, destIDs, []byte("test-pdu"))
	assert.ErrorIs(t, err, ErrClientStopped)
}

func TestSendSyncNoDestinations(t *testing.T) {
	manager, err := NewManager(testConfigWithCerts(t))
	require.NoError(t, err)
	defer manager.Stop()

	client := NewClient(manager, DefaultClientConfig())
	client.Start()
	defer client.Stop()

	ctx := context.Background()
	xid := uuid.New()

	err = client.SendX2Sync(ctx, xid, nil, []byte("test-pdu"))
	assert.ErrorIs(t, err, ErrNoDestinations)

	err = client.SendX3Sync(ctx, xid, []uuid.UUID{}, []byte("test-pdu"))
	assert.ErrorIs(t, err, ErrNoDestinations)
}

func TestBatchDelivery(t *testing.T) {
	certPEM, keyPEM := generateTestCert(t)

	var receivedBytes int64
	listener, port := startTestTLSServerWithCounter(t, certPEM, keyPEM, &receivedBytes)
	defer listener.Close()

	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM(certPEM)

	manager, err := NewManager(testConfigWithCerts(t))
	require.NoError(t, err)
	defer manager.Stop()

	did := uuid.New()
	err = manager.AddDestination(&li.Destination{
		DID:       did,
		Address:   "127.0.0.1",
		Port:      port,
		X2Enabled: true,
		TLSConfig: &tls.Config{
			RootCAs:            certPool,
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
		},
	})
	require.NoError(t, err)

	time.Sleep(500 * time.Millisecond)

	clientConfig := DefaultClientConfig()
	clientConfig.BatchSize = 10
	clientConfig.BatchTimeout = 50 * time.Millisecond

	client := NewClient(manager, clientConfig)
	client.Start()
	defer client.Stop()

	xid := uuid.New()
	data := []byte("test-pdu-data")

	// Send batch.
	for i := 0; i < 20; i++ {
		err := client.SendX2(xid, []uuid.UUID{did}, data)
		require.NoError(t, err)
	}

	// Wait for batch delivery.
	time.Sleep(200 * time.Millisecond)

	stats := client.Stats()
	assert.Equal(t, uint64(20), stats.X2Queued)
	assert.Equal(t, uint64(20), stats.X2Sent)
}

func TestDeliveryBufferedAcrossDestinationRestart(t *testing.T) {
	certPEM, keyPEM := generateTestCert(t)
	server := newRestartableMDF(t, certPEM, keyPEM, 4)
	server.Start(t)
	defer server.Close()

	certPool := x509.NewCertPool()
	require.True(t, certPool.AppendCertsFromPEM(certPEM))

	managerConfig := testConfigWithCerts(t)
	managerConfig.InitialBackoff = 25 * time.Millisecond
	managerConfig.MaxBackoff = 100 * time.Millisecond
	managerConfig.DialTimeout = 100 * time.Millisecond
	manager, err := NewManager(managerConfig)
	require.NoError(t, err)
	defer manager.Stop()

	did := uuid.New()
	require.NoError(t, manager.AddDestination(&li.Destination{
		DID:       did,
		Address:   "127.0.0.1",
		Port:      server.Port(),
		X2Enabled: true,
		TLSConfig: &tls.Config{
			RootCAs:            certPool,
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
		},
	}))
	require.Eventually(t, func() bool { return manager.IsConnected(did) }, 2*time.Second, 10*time.Millisecond)

	clientConfig := DefaultClientConfig()
	clientConfig.BatchSize = 1
	clientConfig.SendTimeout = 200 * time.Millisecond
	clientConfig.ShutdownTimeout = time.Second
	client := NewClient(manager, clientConfig)
	client.Start()
	defer client.Stop()

	xid := uuid.New()
	require.NoError(t, client.SendX2(xid, []uuid.UUID{did}, []byte("0001")))
	assert.Equal(t, "0001", server.Receive(t, time.Second))

	server.Stop()
	require.Eventually(t, func() bool { return !manager.IsConnected(did) }, time.Second, 10*time.Millisecond)

	require.NoError(t, client.SendX2(xid, []uuid.UUID{did}, []byte("0002")))
	require.NoError(t, client.SendX2(xid, []uuid.UUID{did}, []byte("0003")))
	time.Sleep(150 * time.Millisecond)
	assert.Equal(t, int64(2), client.Stats().QueueDepth)

	server.Start(t)
	assert.Equal(t, "0002", server.Receive(t, 2*time.Second))
	assert.Equal(t, "0003", server.Receive(t, 2*time.Second))
	require.Eventually(t, func() bool { return client.QueueDepth() == 0 }, time.Second, 10*time.Millisecond)

	stats := client.Stats()
	assert.Equal(t, uint64(3), stats.X2Sent)
	assert.Equal(t, uint64(0), stats.X2Dropped)
	assert.Greater(t, stats.Retries, uint64(0))
}

// startTestTLSServerWithCounter starts a TLS server that counts received bytes.
func startTestTLSServerWithCounter(t *testing.T, certPEM, keyPEM []byte, counter *int64) (*countingListener, int) {
	t.Helper()

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	require.NoError(t, err)

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.NoClientCert,
		MinVersion:   tls.VersionTLS12,
	}

	listener, err := tls.Listen("tcp", "127.0.0.1:0", tlsConfig)
	require.NoError(t, err)

	port := listener.Addr().(*net.TCPAddr).Port

	cl := &countingListener{
		Listener: listener,
		counter:  counter,
		done:     make(chan struct{}),
	}

	go cl.accept()

	return cl, port
}

type countingListener struct {
	net.Listener
	counter *int64
	done    chan struct{}
}

type restartableMDF struct {
	cert      tls.Certificate
	frameSize int
	address   string
	received  chan string

	mu       sync.Mutex
	listener net.Listener
	conns    map[net.Conn]struct{}
}

func newRestartableMDF(t *testing.T, certPEM, keyPEM []byte, frameSize int) *restartableMDF {
	t.Helper()
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	require.NoError(t, err)
	return &restartableMDF{
		cert:      cert,
		frameSize: frameSize,
		received:  make(chan string, 32),
		conns:     make(map[net.Conn]struct{}),
	}
}

func (s *restartableMDF) Start(t *testing.T) {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	require.Nil(t, s.listener)

	address := s.address
	if address == "" {
		address = "127.0.0.1:0"
	}
	raw, err := net.Listen("tcp", address)
	require.NoError(t, err)
	if s.address == "" {
		s.address = raw.Addr().String()
	}
	s.listener = tls.NewListener(raw, &tls.Config{
		Certificates: []tls.Certificate{s.cert},
		ClientAuth:   tls.NoClientCert,
		MinVersion:   tls.VersionTLS12,
	})
	go s.accept(s.listener)
}

func (s *restartableMDF) Stop() {
	s.mu.Lock()
	listener := s.listener
	s.listener = nil
	conns := make([]net.Conn, 0, len(s.conns))
	for conn := range s.conns {
		conns = append(conns, conn)
	}
	s.mu.Unlock()
	if listener != nil {
		_ = listener.Close()
	}
	for _, conn := range conns {
		_ = conn.Close()
	}
}

func (s *restartableMDF) Close() {
	s.Stop()
}

func (s *restartableMDF) Port() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.listener.Addr().(*net.TCPAddr).Port
}

func (s *restartableMDF) Receive(t *testing.T, timeout time.Duration) string {
	t.Helper()
	select {
	case value := <-s.received:
		return value
	case <-time.After(timeout):
		t.Fatal("timed out waiting for MDF delivery")
		return ""
	}
}

func (s *restartableMDF) accept(listener net.Listener) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		s.mu.Lock()
		s.conns[conn] = struct{}{}
		s.mu.Unlock()
		go s.read(conn)
	}
}

func (s *restartableMDF) read(conn net.Conn) {
	defer func() {
		s.mu.Lock()
		delete(s.conns, conn)
		s.mu.Unlock()
		_ = conn.Close()
	}()
	buf := make([]byte, s.frameSize)
	for {
		if _, err := io.ReadFull(conn, buf); err != nil {
			return
		}
		s.received <- string(append([]byte(nil), buf...))
	}
}

func (cl *countingListener) accept() {
	for {
		conn, err := cl.Listener.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			buf := make([]byte, 4096)
			for {
				n, err := c.Read(buf)
				if err != nil {
					return
				}
				atomic.AddInt64(cl.counter, int64(n))
			}
		}(conn)
	}
}

func TestConcurrentSend(t *testing.T) {
	certPEM, keyPEM := generateTestCert(t)

	listener, port := startTestTLSServer(t, certPEM, keyPEM)
	defer listener.Close()

	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM(certPEM)

	manager, err := NewManager(testConfigWithCerts(t))
	require.NoError(t, err)
	defer manager.Stop()

	did := uuid.New()
	err = manager.AddDestination(&li.Destination{
		DID:       did,
		Address:   "127.0.0.1",
		Port:      port,
		X2Enabled: true,
		X3Enabled: true,
		TLSConfig: &tls.Config{
			RootCAs:            certPool,
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
		},
	})
	require.NoError(t, err)

	time.Sleep(500 * time.Millisecond)

	clientConfig := DefaultClientConfig()
	clientConfig.Workers = 4

	client := NewClient(manager, clientConfig)
	client.Start()
	defer client.Stop()

	xid := uuid.New()
	destIDs := []uuid.UUID{did}

	var wg sync.WaitGroup
	sendCount := 100

	for i := 0; i < sendCount; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			_ = client.SendX2(xid, destIDs, []byte("x2-pdu"))
		}()
		go func() {
			defer wg.Done()
			_ = client.SendX3(xid, destIDs, []byte("x3-pdu"))
		}()
	}

	wg.Wait()

	// Wait for delivery.
	time.Sleep(500 * time.Millisecond)

	stats := client.Stats()
	assert.Equal(t, uint64(sendCount), stats.X2Queued)
	assert.Equal(t, uint64(sendCount), stats.X3Queued)
	assert.Equal(t, uint64(sendCount), stats.X2Sent)
	assert.Equal(t, uint64(sendCount), stats.X3Sent)
}
