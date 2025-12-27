//go:build li

package delivery

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/endorses/lippycat/internal/pkg/li"
)

func TestNewClient(t *testing.T) {
	manager, err := NewManager(DefaultConfig())
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
}

func TestClientConfigDefaults(t *testing.T) {
	manager, err := NewManager(DefaultConfig())
	require.NoError(t, err)
	defer manager.Stop()

	// Test with zero values - should use defaults.
	client := NewClient(manager, ClientConfig{})
	assert.Equal(t, DefaultQueueSize, client.config.QueueSize)
	assert.Equal(t, DefaultWorkers, client.config.Workers)
	assert.Equal(t, DefaultBatchSize, client.config.BatchSize)
	assert.Equal(t, DefaultBatchTimeout, client.config.BatchTimeout)
	assert.Equal(t, DefaultSendTimeout, client.config.SendTimeout)
}

func TestSendX2QueueFull(t *testing.T) {
	manager, err := NewManager(DefaultConfig())
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

	// Second should fail with queue full.
	err = client.SendX2(xid, destIDs, data)
	assert.ErrorIs(t, err, ErrQueueFull)

	stats := client.Stats()
	assert.Equal(t, uint64(1), stats.X2Queued)
	assert.Equal(t, uint64(1), stats.X2Dropped)
}

func TestSendX3QueueFull(t *testing.T) {
	manager, err := NewManager(DefaultConfig())
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
	assert.ErrorIs(t, err, ErrQueueFull)

	stats := client.Stats()
	assert.Equal(t, uint64(1), stats.X3Queued)
	assert.Equal(t, uint64(1), stats.X3Dropped)
}

func TestSendNoDestinations(t *testing.T) {
	manager, err := NewManager(DefaultConfig())
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
	manager, err := NewManager(DefaultConfig())
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
	manager, err := NewManager(DefaultConfig())
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
	manager, err := NewManager(DefaultConfig())
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
	manager, err := NewManager(DefaultConfig())
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
	manager, err := NewManager(DefaultConfig())
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
	manager, err := NewManager(DefaultConfig())
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

	managerConfig := DefaultConfig()
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

	managerConfig := DefaultConfig()
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
	manager, err := NewManager(DefaultConfig())
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
	assert.Equal(t, uint64(1), stats.X2Failed)
	assert.Equal(t, uint64(0), stats.X2Sent)
}

func TestSendX2Sync(t *testing.T) {
	certPEM, keyPEM := generateTestCert(t)

	listener, port := startTestTLSServer(t, certPEM, keyPEM)
	defer listener.Close()

	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM(certPEM)

	managerConfig := DefaultConfig()
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

	managerConfig := DefaultConfig()
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
	manager, err := NewManager(DefaultConfig())
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
	manager, err := NewManager(DefaultConfig())
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
	manager, err := NewManager(DefaultConfig())
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
	manager, err := NewManager(DefaultConfig())
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

	manager, err := NewManager(DefaultConfig())
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

	manager, err := NewManager(DefaultConfig())
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
