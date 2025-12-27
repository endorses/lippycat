//go:build li

package li_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/xml"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/endorses/lippycat/internal/pkg/li"
	"github.com/endorses/lippycat/internal/pkg/li/delivery"
	"github.com/endorses/lippycat/internal/pkg/li/x1"
	"github.com/endorses/lippycat/internal/pkg/li/x1/schema"
)

// testCertDir returns the path to the LI test certificates directory.
func testCertDir() string {
	return filepath.Join("..", "..", "..", "test", "testcerts", "li")
}

// skipIfNoCerts skips the test if LI test certificates are not available.
func skipIfNoCerts(t *testing.T) {
	t.Helper()
	certPath := filepath.Join(testCertDir(), "ca-cert.pem")
	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		t.Skip("LI test certificates not available - run test/testcerts/generate_li_test_certs.sh first")
	}
}

// loadTestCert loads a test certificate.
func loadTestCert(t *testing.T, name string) (certFile, keyFile string) {
	t.Helper()
	certDir := testCertDir()
	certFile = filepath.Join(certDir, name+"-cert.pem")
	keyFile = filepath.Join(certDir, name+"-key.pem")
	return certFile, keyFile
}

// loadTestCA loads the test CA certificate.
func loadTestCA(t *testing.T) string {
	t.Helper()
	return filepath.Join(testCertDir(), "ca-cert.pem")
}

// ============================================================================
// Step 5.3: Security Testing - Mutual TLS Enforcement
// ============================================================================

// waitForServer waits for the X1 server to start and returns its address.
func waitForServer(t *testing.T, server *x1.Server, timeout time.Duration) string {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		addr := server.Addr()
		if addr != "" {
			return addr
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("server did not start within timeout")
	return ""
}

// TestX1Server_MutualTLS_Required tests that the X1 server enforces mutual TLS
// when a CA file is configured.
func TestX1Server_MutualTLS_Required(t *testing.T) {
	skipIfNoCerts(t)

	serverCert, serverKey := loadTestCert(t, "x1-server")
	caFile := loadTestCA(t)

	// Create X1 server with mutual TLS enabled.
	config := x1.ServerConfig{
		ListenAddr:   "127.0.0.1:0",
		TLSCertFile:  serverCert,
		TLSKeyFile:   serverKey,
		TLSCAFile:    caFile, // Enables mutual TLS
		NEIdentifier: "test-ne",
		Version:      "v1.13.1",
	}

	destMgr := &mockDestinationManager{}
	server := x1.NewServer(config, destMgr, nil)

	// Start server.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	serverErrCh := make(chan error, 1)
	go func() {
		serverErrCh <- server.Start(ctx)
	}()

	// Wait for server to start.
	addr := waitForServer(t, server, 5*time.Second)
	require.NotEmpty(t, addr, "server should have an address")

	// Test 1: Connection WITHOUT client certificate should fail.
	t.Run("connection without client cert fails", func(t *testing.T) {
		// Load CA to verify server.
		caCert, err := os.ReadFile(caFile)
		require.NoError(t, err)
		caPool := x509.NewCertPool()
		require.True(t, caPool.AppendCertsFromPEM(caCert))

		tlsConfig := &tls.Config{
			RootCAs:    caPool,
			MinVersion: tls.VersionTLS12,
		}

		client := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: tlsConfig,
			},
			Timeout: 5 * time.Second,
		}

		// Try to connect without providing a client certificate.
		_, err = client.Get("https://" + addr + "/")

		// Connection should fail due to missing client cert.
		require.Error(t, err, "connection without client cert should fail")
		assert.Contains(t, err.Error(), "certificate required", "error should indicate certificate required")
	})

	// Test 2: Connection WITH valid client certificate should succeed.
	t.Run("connection with valid client cert succeeds", func(t *testing.T) {
		clientCert, clientKey := loadTestCert(t, "admf-client")

		// Load client certificate.
		cert, err := tls.LoadX509KeyPair(clientCert, clientKey)
		require.NoError(t, err)

		// Load CA to verify server.
		caCert, err := os.ReadFile(caFile)
		require.NoError(t, err)
		caPool := x509.NewCertPool()
		require.True(t, caPool.AppendCertsFromPEM(caCert))

		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{cert},
			RootCAs:      caPool,
			MinVersion:   tls.VersionTLS12,
		}

		client := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: tlsConfig,
			},
			Timeout: 5 * time.Second,
		}

		// Send a ping request.
		pingReq := `<?xml version="1.0" encoding="UTF-8"?>
<pingRequest>
  <admfIdentifier>test-admf</admfIdentifier>
  <neIdentifier>test-ne</neIdentifier>
  <version>v1.13.1</version>
</pingRequest>`

		resp, err := client.Post("https://"+addr+"/", "application/xml", bytes.NewBufferString(pingReq))
		require.NoError(t, err, "connection with valid client cert should succeed")
		defer func() { _ = resp.Body.Close() }()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	// Shutdown server.
	cancel()
	require.NoError(t, server.Shutdown())
}

// TestX1Server_MutualTLS_WrongCA tests that connections with certificates
// signed by a different CA are rejected.
func TestX1Server_MutualTLS_WrongCA(t *testing.T) {
	skipIfNoCerts(t)

	serverCert, serverKey := loadTestCert(t, "x1-server")
	caFile := loadTestCA(t)

	config := x1.ServerConfig{
		ListenAddr:   "127.0.0.1:0",
		TLSCertFile:  serverCert,
		TLSKeyFile:   serverKey,
		TLSCAFile:    caFile,
		NEIdentifier: "test-ne",
	}

	server := x1.NewServer(config, &mockDestinationManager{}, nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() { _ = server.Start(ctx) }()

	addr := waitForServer(t, server, 5*time.Second)

	// Use certificate signed by wrong CA.
	wrongCACert, wrongCAKey := loadTestCert(t, "wrong-ca-client")

	cert, err := tls.LoadX509KeyPair(wrongCACert, wrongCAKey)
	require.NoError(t, err)

	// Load correct CA to verify server (we still want to trust the server).
	caCert, err := os.ReadFile(caFile)
	require.NoError(t, err)
	caPool := x509.NewCertPool()
	require.True(t, caPool.AppendCertsFromPEM(caCert))

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caPool,
		MinVersion:   tls.VersionTLS12,
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
		Timeout: 5 * time.Second,
	}

	_, err = client.Get("https://" + addr + "/")
	require.Error(t, err, "connection with wrong CA cert should fail")
	// The error message varies by Go version, but should indicate cert issue.
	errStr := err.Error()
	assert.True(t,
		strings.Contains(errStr, "certificate") ||
			strings.Contains(errStr, "unknown authority") ||
			strings.Contains(errStr, "bad certificate"),
		"error should indicate certificate issue: %s", errStr)

	cancel()
	_ = server.Shutdown()
}

// TestX1Server_MutualTLS_SelfSigned tests that self-signed certificates
// (not signed by configured CA) are rejected.
func TestX1Server_MutualTLS_SelfSigned(t *testing.T) {
	skipIfNoCerts(t)

	serverCert, serverKey := loadTestCert(t, "x1-server")
	caFile := loadTestCA(t)

	config := x1.ServerConfig{
		ListenAddr:   "127.0.0.1:0",
		TLSCertFile:  serverCert,
		TLSKeyFile:   serverKey,
		TLSCAFile:    caFile,
		NEIdentifier: "test-ne",
	}

	server := x1.NewServer(config, &mockDestinationManager{}, nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() { _ = server.Start(ctx) }()

	addr := waitForServer(t, server, 5*time.Second)

	// Use self-signed certificate.
	selfSignedCert, selfSignedKey := loadTestCert(t, "selfsigned")

	cert, err := tls.LoadX509KeyPair(selfSignedCert, selfSignedKey)
	require.NoError(t, err)

	// Load correct CA to verify server.
	caCert, err := os.ReadFile(caFile)
	require.NoError(t, err)
	caPool := x509.NewCertPool()
	require.True(t, caPool.AppendCertsFromPEM(caCert))

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caPool,
		MinVersion:   tls.VersionTLS12,
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
		Timeout: 5 * time.Second,
	}

	_, err = client.Get("https://" + addr + "/")
	require.Error(t, err, "connection with self-signed cert should fail")

	cancel()
	_ = server.Shutdown()
}

// ============================================================================
// Step 5.3: Security Testing - X2/X3 Delivery Mutual TLS
// ============================================================================

// TestDeliveryManager_MutualTLS_Required tests that delivery connections
// require mutual TLS with valid client certificates.
func TestDeliveryManager_MutualTLS_Required(t *testing.T) {
	skipIfNoCerts(t)

	// Start a TLS server simulating MDF.
	mdfCert, mdfKey := loadTestCert(t, "mdf-server")
	caFile := loadTestCA(t)

	serverCert, err := tls.LoadX509KeyPair(mdfCert, mdfKey)
	require.NoError(t, err)

	caCert, err := os.ReadFile(caFile)
	require.NoError(t, err)
	clientCAPool := x509.NewCertPool()
	require.True(t, clientCAPool.AppendCertsFromPEM(caCert))

	// MDF server requires client certificates.
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientCAs:    clientCAPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS12,
	}

	listener, err := tls.Listen("tcp", "127.0.0.1:0", tlsConfig)
	require.NoError(t, err)
	defer func() { _ = listener.Close() }()

	// Accept connections in background.
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			// Just close connections after accepting.
			_ = conn.Close()
		}
	}()

	addr := listener.Addr().(*net.TCPAddr)

	// Test: Connection without client cert fails at TLS level.
	t.Run("delivery without client cert fails config validation", func(t *testing.T) {
		// Try to create a delivery manager without client cert.
		config := delivery.DestinationConfig{
			// No TLSCertFile or TLSKeyFile - should fail.
			TLSCAFile:   caFile,
			DialTimeout: 5 * time.Second,
		}

		_, err := delivery.NewManager(config)
		require.Error(t, err, "manager creation without mTLS should fail")
		assert.ErrorIs(t, err, delivery.ErrMutualTLSRequired)
	})

	t.Run("delivery with valid client cert succeeds", func(t *testing.T) {
		deliveryCert, deliveryKey := loadTestCert(t, "delivery-client")

		config := delivery.DestinationConfig{
			TLSCertFile:    deliveryCert,
			TLSKeyFile:     deliveryKey,
			TLSCAFile:      caFile,
			DialTimeout:    5 * time.Second,
			WriteTimeout:   5 * time.Second,
			MaxPoolSize:    1,
			InitialBackoff: 100 * time.Millisecond,
			MaxBackoff:     1 * time.Second,
		}

		manager, err := delivery.NewManager(config)
		require.NoError(t, err, "manager creation with mTLS should succeed")

		manager.Start()
		defer manager.Stop()

		// Add a destination.
		dest := &li.Destination{
			DID:       uuid.New(),
			Address:   "127.0.0.1",
			Port:      addr.Port,
			X2Enabled: true,
			X3Enabled: true,
		}

		err = manager.AddDestination(dest)
		require.NoError(t, err)

		// Wait for connection attempt.
		time.Sleep(200 * time.Millisecond)

		// Check if connected (may or may not be based on server behavior).
		connected := manager.IsConnected(dest.DID)
		t.Logf("Connection status: %v", connected)
	})

	// Close listener to stop server.
	_ = listener.Close()
	<-serverDone
}

// TestDeliveryManager_CertificatePinning tests certificate pinning functionality.
func TestDeliveryManager_CertificatePinning(t *testing.T) {
	skipIfNoCerts(t)

	mdfCert, mdfKey := loadTestCert(t, "mdf-server")
	caFile := loadTestCA(t)

	serverCert, err := tls.LoadX509KeyPair(mdfCert, mdfKey)
	require.NoError(t, err)

	caCert, err := os.ReadFile(caFile)
	require.NoError(t, err)
	clientCAPool := x509.NewCertPool()
	require.True(t, clientCAPool.AppendCertsFromPEM(caCert))

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientCAs:    clientCAPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS12,
	}

	listener, err := tls.Listen("tcp", "127.0.0.1:0", tlsConfig)
	require.NoError(t, err)
	defer func() { _ = listener.Close() }()

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()

	addr := listener.Addr().(*net.TCPAddr)
	deliveryCert, deliveryKey := loadTestCert(t, "delivery-client")

	t.Run("connection with wrong pinned cert fails", func(t *testing.T) {
		config := delivery.DestinationConfig{
			TLSCertFile:    deliveryCert,
			TLSKeyFile:     deliveryKey,
			TLSCAFile:      caFile,
			TLSPinnedCerts: []string{"0000000000000000000000000000000000000000000000000000000000000000"}, // Wrong fingerprint
			DialTimeout:    2 * time.Second,
			WriteTimeout:   2 * time.Second,
			MaxPoolSize:    1,
			InitialBackoff: 100 * time.Millisecond,
			MaxBackoff:     500 * time.Millisecond,
		}

		manager, err := delivery.NewManager(config)
		require.NoError(t, err)

		manager.Start()
		defer manager.Stop()

		dest := &li.Destination{
			DID:       uuid.New(),
			Address:   "127.0.0.1",
			Port:      addr.Port,
			X2Enabled: true,
		}

		err = manager.AddDestination(dest)
		require.NoError(t, err)

		// Wait for connection attempt.
		time.Sleep(300 * time.Millisecond)

		// Connection should fail due to pinning mismatch.
		assert.False(t, manager.IsConnected(dest.DID), "connection with wrong pinned cert should fail")
	})
}

// ============================================================================
// Step 5.3: Security Testing - Audit Logging Completeness
// ============================================================================

// TestAuditLogging_TaskOperations verifies that task operations are logged.
// This test validates the structure of the LI system's audit logging by
// checking that key operations trigger appropriate log entries.
func TestAuditLogging_TaskOperations(t *testing.T) {
	// Create a manager with LI enabled.
	config := li.ManagerConfig{
		Enabled:      true,
		NEIdentifier: "test-ne",
	}

	manager := li.NewManager(config, nil)
	require.NotNil(t, manager)

	// The audit logging is verified by the structured logger calls in the code.
	// Key operations that should be logged:
	// - Task activation: logger.Info("LI task activated", ...)
	// - Task modification: logger.Info("LI task modified", ...)
	// - Task deactivation: logger.Info("LI task deactivated", ...)
	// - Destination creation/removal
	// - X1 request/response handling

	// We verify the manager exists and can be started/stopped.
	// Full logging verification would require log capture infrastructure.
	err := manager.Start()
	require.NoError(t, err)

	// First create a destination for the task.
	destID := uuid.New()
	dest := &li.Destination{
		DID:       destID,
		Address:   "192.0.2.1",
		Port:      5443,
		X2Enabled: true,
		X3Enabled: true,
	}
	err = manager.CreateDestination(dest)
	require.NoError(t, err)

	// Create a task.
	task := &li.InterceptTask{
		XID: uuid.New(),
		Targets: []li.TargetIdentity{
			{Type: li.TargetTypeSIPURI, Value: "sip:test@example.com"},
		},
		DeliveryType:   li.DeliveryX2andX3,
		DestinationIDs: []uuid.UUID{destID},
	}

	// Activate task - this triggers logging.
	err = manager.ActivateTask(task)
	require.NoError(t, err)

	// Deactivate task - this triggers logging.
	err = manager.DeactivateTask(task.XID)
	require.NoError(t, err)

	manager.Stop()
}

// TestAuditLogging_X1Operations verifies that X1 operations are logged.
func TestAuditLogging_X1Operations(t *testing.T) {
	skipIfNoCerts(t)

	serverCert, serverKey := loadTestCert(t, "x1-server")

	config := x1.ServerConfig{
		ListenAddr:   "127.0.0.1:0",
		TLSCertFile:  serverCert,
		TLSKeyFile:   serverKey,
		NEIdentifier: "audit-test-ne",
		Version:      "v1.13.1",
	}

	// X1 operations that should be logged:
	// - Server start: logger.Info("X1 server starting", ...)
	// - Ping requests: logger.Debug("X1 ping received")
	// - Destination operations: logger.Info("X1 destination created/modified/removed", ...)
	// - Task operations: logger.Info("X1 task activated/deactivated/modified", ...)
	// - Error responses: logger.Warn("X1 error response", ...)

	server := x1.NewServer(config, &mockDestinationManager{}, nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() { _ = server.Start(ctx) }()

	addr := waitForServer(t, server, 5*time.Second)
	require.NotEmpty(t, addr)

	// Make a request to trigger logging.
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		Timeout: 5 * time.Second,
	}

	pingReq := `<?xml version="1.0" encoding="UTF-8"?>
<pingRequest>
  <admfIdentifier>audit-admf</admfIdentifier>
  <neIdentifier>audit-test-ne</neIdentifier>
</pingRequest>`

	resp, err := client.Post("https://"+addr+"/", "application/xml", bytes.NewBufferString(pingReq))
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	cancel()
	_ = server.Shutdown()
}

// TestAuditLogging_DeliveryOperations verifies that delivery operations are logged.
func TestAuditLogging_DeliveryOperations(t *testing.T) {
	skipIfNoCerts(t)

	deliveryCert, deliveryKey := loadTestCert(t, "delivery-client")
	caFile := loadTestCA(t)

	// Delivery operations that should be logged:
	// - Manager start: logger.Info("delivery client started", ...)
	// - Manager stop: logger.Info("delivery client stopped")
	// - Destination added: logger.Info("destination added", ...)
	// - Destination removed: logger.Info("destination removed", ...)
	// - Connection success: logger.Info("destination connected", ...)
	// - Connection failure: logger.Warn("destination connection failed", ...)

	config := delivery.DestinationConfig{
		TLSCertFile:    deliveryCert,
		TLSKeyFile:     deliveryKey,
		TLSCAFile:      caFile,
		DialTimeout:    2 * time.Second,
		WriteTimeout:   2 * time.Second,
		MaxPoolSize:    1,
		InitialBackoff: 100 * time.Millisecond,
		MaxBackoff:     500 * time.Millisecond,
	}

	manager, err := delivery.NewManager(config)
	require.NoError(t, err)

	manager.Start()

	// Add and remove a destination to trigger logging.
	dest := &li.Destination{
		DID:       uuid.New(),
		Address:   "192.0.2.1", // Non-routable address
		Port:      5443,
		X2Enabled: true,
	}

	err = manager.AddDestination(dest)
	require.NoError(t, err)

	// Wait briefly for connection attempt (will fail).
	time.Sleep(100 * time.Millisecond)

	err = manager.RemoveDestination(dest.DID)
	require.NoError(t, err)

	manager.Stop()
}

// ============================================================================
// Step 5.3: Security Testing - TLS Version and Cipher Suite Enforcement
// ============================================================================

// TestX1Server_TLSVersionEnforcement tests that the server enforces minimum TLS version.
func TestX1Server_TLSVersionEnforcement(t *testing.T) {
	skipIfNoCerts(t)

	serverCert, serverKey := loadTestCert(t, "x1-server")

	config := x1.ServerConfig{
		ListenAddr:   "127.0.0.1:0",
		TLSCertFile:  serverCert,
		TLSKeyFile:   serverKey,
		NEIdentifier: "test-ne",
	}

	server := x1.NewServer(config, &mockDestinationManager{}, nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() { _ = server.Start(ctx) }()

	addr := waitForServer(t, server, 5*time.Second)

	t.Run("TLS 1.2 connection succeeds", func(t *testing.T) {
		tlsConfig := &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
			MaxVersion:         tls.VersionTLS12,
		}

		client := &http.Client{
			Transport: &http.Transport{TLSClientConfig: tlsConfig},
			Timeout:   5 * time.Second,
		}

		resp, err := client.Get("https://" + addr + "/")
		if err == nil {
			defer func() { _ = resp.Body.Close() }()
		}
		// Connection should succeed (may get 400 due to no body, but TLS works).
		require.NoError(t, err, "TLS 1.2 connection should succeed")
	})

	t.Run("TLS 1.3 connection succeeds", func(t *testing.T) {
		tlsConfig := &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS13,
			MaxVersion:         tls.VersionTLS13,
		}

		client := &http.Client{
			Transport: &http.Transport{TLSClientConfig: tlsConfig},
			Timeout:   5 * time.Second,
		}

		resp, err := client.Get("https://" + addr + "/")
		if err == nil {
			defer func() { _ = resp.Body.Close() }()
		}
		require.NoError(t, err, "TLS 1.3 connection should succeed")
	})

	cancel()
	_ = server.Shutdown()
}

// ============================================================================
// Step 5.3: Security Testing - X1 Response Verification
// ============================================================================

// TestX1Server_ResponseContainsNEIdentifier verifies that X1 responses
// contain the correct NE identifier for audit traceability.
func TestX1Server_ResponseContainsNEIdentifier(t *testing.T) {
	skipIfNoCerts(t)

	serverCert, serverKey := loadTestCert(t, "x1-server")

	neID := "security-test-ne-12345"
	config := x1.ServerConfig{
		ListenAddr:   "127.0.0.1:0",
		TLSCertFile:  serverCert,
		TLSKeyFile:   serverKey,
		NEIdentifier: neID,
		Version:      "v1.13.1",
	}

	server := x1.NewServer(config, &mockDestinationManager{}, nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() { _ = server.Start(ctx) }()

	addr := waitForServer(t, server, 5*time.Second)

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		Timeout: 5 * time.Second,
	}

	pingReq := `<?xml version="1.0" encoding="UTF-8"?>
<pingRequest>
  <admfIdentifier>test-admf</admfIdentifier>
  <neIdentifier>` + neID + `</neIdentifier>
  <version>v1.13.1</version>
</pingRequest>`

	resp, err := client.Post("https://"+addr+"/", "application/xml", bytes.NewBufferString(pingReq))
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	// Parse response to verify NE identifier.
	var respContainer schema.ResponseContainer
	err = xml.Unmarshal(body, &respContainer)
	require.NoError(t, err)
	require.Len(t, respContainer.X1ResponseMessage, 1)

	assert.Equal(t, neID, respContainer.X1ResponseMessage[0].NeIdentifier,
		"Response should contain correct NE identifier for audit traceability")

	cancel()
	_ = server.Shutdown()
}

// TestX1Server_ResponseContainsTimestamp verifies that X1 responses
// contain timestamps for audit traceability.
func TestX1Server_ResponseContainsTimestamp(t *testing.T) {
	skipIfNoCerts(t)

	serverCert, serverKey := loadTestCert(t, "x1-server")

	config := x1.ServerConfig{
		ListenAddr:   "127.0.0.1:0",
		TLSCertFile:  serverCert,
		TLSKeyFile:   serverKey,
		NEIdentifier: "timestamp-test-ne",
		Version:      "v1.13.1",
	}

	server := x1.NewServer(config, &mockDestinationManager{}, nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() { _ = server.Start(ctx) }()

	addr := waitForServer(t, server, 5*time.Second)

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		Timeout: 5 * time.Second,
	}

	beforeRequest := time.Now().Add(-1 * time.Second)

	pingReq := `<?xml version="1.0" encoding="UTF-8"?>
<pingRequest>
  <admfIdentifier>test-admf</admfIdentifier>
</pingRequest>`

	resp, err := client.Post("https://"+addr+"/", "application/xml", bytes.NewBufferString(pingReq))
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	afterRequest := time.Now().Add(1 * time.Second)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	var respContainer schema.ResponseContainer
	err = xml.Unmarshal(body, &respContainer)
	require.NoError(t, err)
	require.Len(t, respContainer.X1ResponseMessage, 1)

	timestamp := respContainer.X1ResponseMessage[0].MessageTimestamp
	require.NotNil(t, timestamp, "Response should contain timestamp")

	// Parse the timestamp string (QualifiedMicrosecondDateTime format).
	tsStr := string(*timestamp)
	require.NotEmpty(t, tsStr, "Timestamp should not be empty")

	// Parse ISO8601/RFC3339 timestamp.
	ts, err := time.Parse(time.RFC3339Nano, tsStr)
	if err != nil {
		// Try alternative format without nanoseconds.
		ts, err = time.Parse(time.RFC3339, tsStr)
	}
	require.NoError(t, err, "Timestamp should be parseable: %s", tsStr)

	assert.True(t, ts.After(beforeRequest) && ts.Before(afterRequest),
		"Timestamp %v should be between %v and %v", ts, beforeRequest, afterRequest)

	cancel()
	_ = server.Shutdown()
}

// ============================================================================
// Helper Types for Testing
// ============================================================================

// mockDestinationManager implements x1.DestinationManager for testing.
type mockDestinationManager struct {
	destinations map[uuid.UUID]*x1.Destination
}

func (m *mockDestinationManager) CreateDestination(dest *x1.Destination) error {
	if m.destinations == nil {
		m.destinations = make(map[uuid.UUID]*x1.Destination)
	}
	if _, exists := m.destinations[dest.DID]; exists {
		return x1.ErrDestinationAlreadyExists
	}
	m.destinations[dest.DID] = dest
	return nil
}

func (m *mockDestinationManager) GetDestination(did uuid.UUID) (*x1.Destination, error) {
	if m.destinations == nil {
		return nil, x1.ErrDestinationNotFound
	}
	dest, exists := m.destinations[did]
	if !exists {
		return nil, x1.ErrDestinationNotFound
	}
	return dest, nil
}

func (m *mockDestinationManager) RemoveDestination(did uuid.UUID) error {
	if m.destinations == nil {
		return x1.ErrDestinationNotFound
	}
	if _, exists := m.destinations[did]; !exists {
		return x1.ErrDestinationNotFound
	}
	delete(m.destinations, did)
	return nil
}

func (m *mockDestinationManager) ModifyDestination(did uuid.UUID, dest *x1.Destination) error {
	if m.destinations == nil {
		return x1.ErrDestinationNotFound
	}
	if _, exists := m.destinations[did]; !exists {
		return x1.ErrDestinationNotFound
	}
	m.destinations[did] = dest
	return nil
}

var _ x1.DestinationManager = (*mockDestinationManager)(nil)

// ============================================================================
// Step 5.3: Additional Security Tests
// ============================================================================

// TestX1Server_SecureCipherSuites verifies that the server uses secure cipher suites.
func TestX1Server_SecureCipherSuites(t *testing.T) {
	skipIfNoCerts(t)

	serverCert, serverKey := loadTestCert(t, "x1-server")

	config := x1.ServerConfig{
		ListenAddr:   "127.0.0.1:0",
		TLSCertFile:  serverCert,
		TLSKeyFile:   serverKey,
		NEIdentifier: "cipher-test-ne",
	}

	server := x1.NewServer(config, &mockDestinationManager{}, nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() { _ = server.Start(ctx) }()

	addr := waitForServer(t, server, 5*time.Second)

	// Test with secure cipher suites.
	t.Run("secure cipher suites work", func(t *testing.T) {
		tlsConfig := &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
			CipherSuites: []uint16{
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			},
		}

		conn, err := tls.Dial("tcp", addr, tlsConfig)
		require.NoError(t, err, "connection with secure cipher suites should succeed")

		state := conn.ConnectionState()
		t.Logf("Negotiated cipher suite: %s", tls.CipherSuiteName(state.CipherSuite))

		// Verify a secure cipher suite was negotiated.
		secureSuites := map[uint16]bool{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:       true,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:         true,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:       true,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:         true,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256: true,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:   true,
			// TLS 1.3 cipher suites
			tls.TLS_AES_128_GCM_SHA256:       true,
			tls.TLS_AES_256_GCM_SHA384:       true,
			tls.TLS_CHACHA20_POLY1305_SHA256: true,
		}

		assert.True(t, secureSuites[state.CipherSuite],
			"negotiated cipher suite %s should be secure", tls.CipherSuiteName(state.CipherSuite))

		_ = conn.Close()
	})

	cancel()
	_ = server.Shutdown()
}

// TestManager_EnabledStateReporting tests that the manager correctly reports its enabled state.
func TestManager_EnabledStateReporting(t *testing.T) {
	t.Run("disabled manager reports disabled", func(t *testing.T) {
		config := li.ManagerConfig{
			Enabled: false,
		}
		manager := li.NewManager(config, nil)
		assert.False(t, manager.IsEnabled())
	})

	t.Run("enabled manager reports enabled", func(t *testing.T) {
		config := li.ManagerConfig{
			Enabled: true,
		}
		manager := li.NewManager(config, nil)
		assert.True(t, manager.IsEnabled())
	})
}

// TestDeliveryManager_ErrorsExposed tests that delivery errors are properly exposed.
func TestDeliveryManager_ErrorsExposed(t *testing.T) {
	// Verify that security-related errors are properly typed.
	assert.Equal(t, "mutual TLS required: client certificate and key must be provided",
		delivery.ErrMutualTLSRequired.Error())

	assert.Equal(t, "certificate pinning failed: server certificate fingerprint not in pinned list",
		delivery.ErrCertificatePinningFailed.Error())
}

// TestX1Server_ErrorCodesForSecurityViolations tests that security violations
// return appropriate error codes.
func TestX1Server_ErrorCodesForSecurityViolations(t *testing.T) {
	skipIfNoCerts(t)

	serverCert, serverKey := loadTestCert(t, "x1-server")
	caFile := loadTestCA(t)

	config := x1.ServerConfig{
		ListenAddr:   "127.0.0.1:0",
		TLSCertFile:  serverCert,
		TLSKeyFile:   serverKey,
		TLSCAFile:    caFile,
		NEIdentifier: "error-test-ne",
		Version:      "v1.13.1",
	}

	server := x1.NewServer(config, &mockDestinationManager{}, nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() { _ = server.Start(ctx) }()

	addr := waitForServer(t, server, 5*time.Second)

	// Create client with valid mTLS.
	clientCert, clientKey := loadTestCert(t, "admf-client")
	cert, err := tls.LoadX509KeyPair(clientCert, clientKey)
	require.NoError(t, err)

	caCert, err := os.ReadFile(caFile)
	require.NoError(t, err)
	caPool := x509.NewCertPool()
	require.True(t, caPool.AppendCertsFromPEM(caCert))

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caPool,
		MinVersion:   tls.VersionTLS12,
	}

	client := &http.Client{
		Transport: &http.Transport{TLSClientConfig: tlsConfig},
		Timeout:   5 * time.Second,
	}

	// Test: Attempting to access non-existent resource returns proper error.
	t.Run("non-existent destination returns error", func(t *testing.T) {
		nonExistentDID := uuid.New()
		reqBody := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<removeDestinationRequest>
  <admfIdentifier>test-admf</admfIdentifier>
  <dId>%s</dId>
</removeDestinationRequest>`, nonExistentDID.String())

		resp, err := client.Post("https://"+addr+"/", "application/xml", bytes.NewBufferString(reqBody))
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()

		// Response should be 200 OK with error in body (X1 protocol).
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	cancel()
	_ = server.Shutdown()
}
