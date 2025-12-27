//go:build li

package delivery

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
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

// testCertDirDest returns the path to the LI test certificates directory.
func testCertDirDest() string {
	return filepath.Join("..", "..", "..", "..", "test", "testcerts", "li")
}

// testConfigWithCertsDest returns a DestinationConfig with test TLS certificates.
func testConfigWithCertsDest(t *testing.T) DestinationConfig {
	t.Helper()
	certDir := testCertDirDest()
	certPath := filepath.Join(certDir, "delivery-client-cert.pem")
	keyPath := filepath.Join(certDir, "delivery-client-key.pem")
	caPath := filepath.Join(certDir, "ca-cert.pem")

	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		t.Skip("LI test certificates not available - run test/testcerts/generate_li_test_certs.sh first")
	}

	config := DefaultConfig()
	config.TLSCertFile = certPath
	config.TLSKeyFile = keyPath
	config.TLSCAFile = caPath
	return config
}

// generateTestCert generates a self-signed certificate for testing.
func generateTestCert(t *testing.T) (certPEM, keyPEM []byte) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:              []string{"localhost"},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	require.NoError(t, err)

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	return certPEM, keyPEM
}

// startTestTLSServer starts a TLS server for testing.
func startTestTLSServer(t *testing.T, certPEM, keyPEM []byte) (net.Listener, int) {
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

	// Accept connections in background.
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			// Just hold the connection open.
			go func(c net.Conn) {
				buf := make([]byte, 1024)
				for {
					_, err := c.Read(buf)
					if err != nil {
						return
					}
				}
			}(conn)
		}
	}()

	return listener, port
}

func TestNewManager(t *testing.T) {
	config := testConfigWithCertsDest(t)

	manager, err := NewManager(config)
	require.NoError(t, err)
	assert.NotNil(t, manager)
	assert.Equal(t, 0, manager.DestinationCount())
}

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()

	assert.Equal(t, DefaultDialTimeout, config.DialTimeout)
	assert.Equal(t, DefaultWriteTimeout, config.WriteTimeout)
	assert.Equal(t, DefaultInitialBackoff, config.InitialBackoff)
	assert.Equal(t, DefaultMaxBackoff, config.MaxBackoff)
	assert.Equal(t, DefaultBackoffMultiplier, config.BackoffMultiplier)
	assert.Equal(t, DefaultMaxPoolSize, config.MaxPoolSize)
	assert.Equal(t, DefaultKeepAliveInterval, config.KeepAliveInterval)
}

func TestAddRemoveDestination(t *testing.T) {
	config := testConfigWithCertsDest(t)
	manager, err := NewManager(config)
	require.NoError(t, err)
	defer manager.Stop()

	did := uuid.New()
	dest := &li.Destination{
		DID:       did,
		Address:   "127.0.0.1",
		Port:      9999,
		X2Enabled: true,
		X3Enabled: true,
	}

	// Add destination.
	err = manager.AddDestination(dest)
	require.NoError(t, err)
	assert.Equal(t, 1, manager.DestinationCount())

	// Verify it exists.
	retrieved, err := manager.GetDestination(did)
	require.NoError(t, err)
	assert.Equal(t, did, retrieved.DID)
	assert.Equal(t, "127.0.0.1", retrieved.Address)

	// Add duplicate should fail.
	err = manager.AddDestination(dest)
	assert.ErrorIs(t, err, ErrDestinationExists)

	// Remove destination.
	err = manager.RemoveDestination(did)
	require.NoError(t, err)
	assert.Equal(t, 0, manager.DestinationCount())

	// Remove non-existent should fail.
	err = manager.RemoveDestination(did)
	assert.ErrorIs(t, err, ErrDestinationNotFound)
}

func TestGetDestinationNotFound(t *testing.T) {
	config := testConfigWithCertsDest(t)
	manager, err := NewManager(config)
	require.NoError(t, err)
	defer manager.Stop()

	_, err = manager.GetDestination(uuid.New())
	assert.ErrorIs(t, err, ErrDestinationNotFound)
}

func TestConnectionPooling(t *testing.T) {
	pool := newConnPool(2)

	// Pool should be empty.
	assert.Equal(t, 0, pool.size())
	assert.Nil(t, pool.get())

	// Create mock pooled connections.
	conn1 := &pooledConn{createdAt: time.Now()}
	conn2 := &pooledConn{createdAt: time.Now()}
	conn3 := &pooledConn{createdAt: time.Now()}

	// Put connections.
	assert.True(t, pool.put(conn1))
	assert.True(t, pool.put(conn2))
	assert.Equal(t, 2, pool.size())

	// Pool full, should reject.
	assert.False(t, pool.put(conn3))

	// Get connections (LIFO).
	got := pool.get()
	assert.Equal(t, conn2, got)
	assert.Equal(t, 1, pool.size())

	got = pool.get()
	assert.Equal(t, conn1, got)
	assert.Equal(t, 0, pool.size())

	// Empty pool.
	assert.Nil(t, pool.get())
}

func TestConnectionPoolClose(t *testing.T) {
	pool := newConnPool(2)

	// Close empty pool.
	pool.close()

	// Operations after close.
	conn := &pooledConn{createdAt: time.Now()}
	assert.False(t, pool.put(conn))
	assert.Nil(t, pool.get())
}

func TestDestinationConnection(t *testing.T) {
	certPEM, keyPEM := generateTestCert(t)

	listener, port := startTestTLSServer(t, certPEM, keyPEM)
	defer listener.Close()

	// Parse the cert for client trust.
	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM(certPEM)

	config := testConfigWithCertsDest(t)
	config.DialTimeout = 2 * time.Second
	config.InitialBackoff = 100 * time.Millisecond

	manager, err := NewManager(config)
	require.NoError(t, err)
	defer manager.Stop()

	// Create destination with custom TLS config.
	did := uuid.New()
	dest := &li.Destination{
		DID:       did,
		Address:   "127.0.0.1",
		Port:      port,
		X2Enabled: true,
		TLSConfig: &tls.Config{
			RootCAs:            certPool,
			InsecureSkipVerify: true, // For test with self-signed cert.
			MinVersion:         tls.VersionTLS12,
		},
	}

	err = manager.AddDestination(dest)
	require.NoError(t, err)

	// Wait for connection.
	time.Sleep(500 * time.Millisecond)

	// Check connection status.
	assert.True(t, manager.IsConnected(did))

	// Get stats.
	stats, err := manager.Stats(did)
	require.NoError(t, err)
	assert.Greater(t, stats.ConnectAttempts, uint64(0))
	assert.Greater(t, stats.ConnectSuccesses, uint64(0))
}

func TestDestinationConnectionFailure(t *testing.T) {
	config := testConfigWithCertsDest(t)
	config.DialTimeout = 500 * time.Millisecond
	config.InitialBackoff = 100 * time.Millisecond

	manager, err := NewManager(config)
	require.NoError(t, err)
	defer manager.Stop()

	did := uuid.New()
	dest := &li.Destination{
		DID:     did,
		Address: "127.0.0.1",
		Port:    1, // Likely unavailable port.
	}

	err = manager.AddDestination(dest)
	require.NoError(t, err)

	// Wait for connection attempt.
	time.Sleep(1 * time.Second)

	// Should not be connected.
	assert.False(t, manager.IsConnected(did))

	// Stats should show failure.
	stats, err := manager.Stats(did)
	require.NoError(t, err)
	assert.Greater(t, stats.ConnectAttempts, uint64(0))
	assert.Greater(t, stats.ConnectFailures, uint64(0))
}

func TestExponentialBackoff(t *testing.T) {
	config := testConfigWithCertsDest(t)
	config.InitialBackoff = 50 * time.Millisecond
	config.MaxBackoff = 400 * time.Millisecond
	config.BackoffMultiplier = 2.0
	config.DialTimeout = 100 * time.Millisecond

	manager, err := NewManager(config)
	require.NoError(t, err)
	defer manager.Stop()

	did := uuid.New()
	dest := &li.Destination{
		DID:     did,
		Address: "127.0.0.1",
		Port:    1, // Unavailable port.
	}

	start := time.Now()
	err = manager.AddDestination(dest)
	require.NoError(t, err)

	// Wait for multiple reconnection attempts.
	time.Sleep(1 * time.Second)

	stats, err := manager.Stats(did)
	require.NoError(t, err)

	// Should have multiple attempts due to backoff.
	assert.Greater(t, stats.ConnectAttempts, uint64(1))

	elapsed := time.Since(start)
	t.Logf("Attempts: %d in %v", stats.ConnectAttempts, elapsed)
}

func TestUpdateDestination(t *testing.T) {
	certPEM, keyPEM := generateTestCert(t)

	listener, port := startTestTLSServer(t, certPEM, keyPEM)
	defer listener.Close()

	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM(certPEM)

	config := testConfigWithCertsDest(t)
	manager, err := NewManager(config)
	require.NoError(t, err)
	defer manager.Stop()

	did := uuid.New()
	dest := &li.Destination{
		DID:       did,
		Address:   "127.0.0.1",
		Port:      port,
		X2Enabled: true,
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

	// Update without address change.
	dest.X3Enabled = true
	err = manager.UpdateDestination(dest)
	require.NoError(t, err)

	// Verify update.
	retrieved, err := manager.GetDestination(did)
	require.NoError(t, err)
	assert.True(t, retrieved.X3Enabled)
}

func TestUpdateNonExistentDestination(t *testing.T) {
	config := testConfigWithCertsDest(t)
	manager, err := NewManager(config)
	require.NoError(t, err)
	defer manager.Stop()

	dest := &li.Destination{
		DID:     uuid.New(),
		Address: "127.0.0.1",
		Port:    9999,
	}

	err = manager.UpdateDestination(dest)
	assert.ErrorIs(t, err, ErrDestinationNotFound)
}

func TestShutdown(t *testing.T) {
	config := testConfigWithCertsDest(t)
	manager, err := NewManager(config)
	require.NoError(t, err)

	did := uuid.New()
	dest := &li.Destination{
		DID:     did,
		Address: "127.0.0.1",
		Port:    9999,
	}

	err = manager.AddDestination(dest)
	require.NoError(t, err)

	// Stop should complete cleanly.
	manager.Stop()

	// Operations after shutdown should fail.
	err = manager.AddDestination(&li.Destination{
		DID:     uuid.New(),
		Address: "127.0.0.1",
		Port:    9998,
	})
	assert.ErrorIs(t, err, ErrShuttingDown)
}

func TestRecordStats(t *testing.T) {
	config := testConfigWithCertsDest(t)
	manager, err := NewManager(config)
	require.NoError(t, err)
	defer manager.Stop()

	did := uuid.New()
	dest := &li.Destination{
		DID:     did,
		Address: "127.0.0.1",
		Port:    9999,
	}

	err = manager.AddDestination(dest)
	require.NoError(t, err)

	// Record some stats.
	manager.RecordBytesSent(did, 1024)
	manager.RecordBytesSent(did, 512)
	manager.RecordWriteError(did)

	stats, err := manager.Stats(did)
	require.NoError(t, err)

	assert.Equal(t, uint64(1536), stats.BytesSent)
	assert.Equal(t, uint64(2), stats.PDUsSent)
	assert.Equal(t, uint64(1), stats.WriteErrors)
}

func TestAllStats(t *testing.T) {
	config := testConfigWithCertsDest(t)
	manager, err := NewManager(config)
	require.NoError(t, err)
	defer manager.Stop()

	did1 := uuid.New()
	did2 := uuid.New()

	err = manager.AddDestination(&li.Destination{DID: did1, Address: "127.0.0.1", Port: 9999})
	require.NoError(t, err)
	err = manager.AddDestination(&li.Destination{DID: did2, Address: "127.0.0.1", Port: 9998})
	require.NoError(t, err)

	manager.RecordBytesSent(did1, 100)
	manager.RecordBytesSent(did2, 200)

	allStats := manager.AllStats()
	assert.Len(t, allStats, 2)
	assert.Equal(t, uint64(100), allStats[did1].BytesSent)
	assert.Equal(t, uint64(200), allStats[did2].BytesSent)
}

func TestConcurrentAccess(t *testing.T) {
	config := testConfigWithCertsDest(t)
	manager, err := NewManager(config)
	require.NoError(t, err)
	defer manager.Stop()

	var wg sync.WaitGroup
	var addCount, removeCount int32

	// Concurrent adds and removes.
	for i := 0; i < 10; i++ {
		wg.Add(2)

		go func() {
			defer wg.Done()
			did := uuid.New()
			dest := &li.Destination{
				DID:     did,
				Address: "127.0.0.1",
				Port:    9999,
			}
			if err := manager.AddDestination(dest); err == nil {
				atomic.AddInt32(&addCount, 1)
			}
		}()

		go func() {
			defer wg.Done()
			// Try to remove a random destination.
			if err := manager.RemoveDestination(uuid.New()); err == nil {
				atomic.AddInt32(&removeCount, 1)
			}
		}()
	}

	wg.Wait()

	// Most adds should succeed, most removes should fail (not found).
	assert.Greater(t, addCount, int32(0))
}

func TestGetConnectionNotConnected(t *testing.T) {
	config := testConfigWithCertsDest(t)
	manager, err := NewManager(config)
	require.NoError(t, err)
	defer manager.Stop()

	did := uuid.New()
	dest := &li.Destination{
		DID:     did,
		Address: "127.0.0.1",
		Port:    1, // Unavailable port.
	}

	err = manager.AddDestination(dest)
	require.NoError(t, err)

	// Don't wait for connection - try immediately.
	_, err = manager.GetConnection(did)
	// Either not connected or pool exhausted.
	assert.Error(t, err)
}

func TestStatsForNonExistentDestination(t *testing.T) {
	config := testConfigWithCertsDest(t)
	manager, err := NewManager(config)
	require.NoError(t, err)
	defer manager.Stop()

	_, err = manager.Stats(uuid.New())
	assert.ErrorIs(t, err, ErrDestinationNotFound)
}
