//go:build processor || tap || all

package test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/processor"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// TestIntegration_TLS_MutualAuth tests TLS with mutual authentication (mTLS)
func TestIntegration_TLS_MutualAuth(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Load test certificates
	certsDir := filepath.Join("testcerts")

	// Skip if certificates don't exist (not in integration test environment)
	if _, err := os.Stat(filepath.Join(certsDir, "ca-cert.pem")); os.IsNotExist(err) {
		t.Skip("Skipping TLS test: certificates not found (run in integration test environment with generated certs)")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	caCert, err := os.ReadFile(filepath.Join(certsDir, "ca-cert.pem"))
	require.NoError(t, err, "Failed to read CA certificate")

	caCertPool := x509.NewCertPool()
	ok := caCertPool.AppendCertsFromPEM(caCert)
	require.True(t, ok, "Failed to parse CA certificate")

	// Start processor with TLS enabled
	processorAddr := "127.0.0.1:50058"
	proc, err := startTLSProcessor(t, ctx, processorAddr, certsDir, true)
	require.NoError(t, err, "Failed to start TLS processor")
	defer proc.Shutdown()

	// Wait for processor to be ready (TLS needs more time to initialize)
	// CI with race detector can be slow
	time.Sleep(5 * time.Second)

	// Load hunter client certificate
	hunterCert, err := tls.LoadX509KeyPair(
		filepath.Join(certsDir, "hunter-cert.pem"),
		filepath.Join(certsDir, "hunter-key.pem"),
	)
	require.NoError(t, err, "Failed to load hunter certificate")

	// Create TLS credentials for hunter (client)
	hunterTLSConfig := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{hunterCert},
		RootCAs:      caCertPool,
		ServerName:   "processor.test.local",
	}

	// Connect to processor with TLS
	creds := credentials.NewTLS(hunterTLSConfig)

	dialCtx, dialCancel := context.WithTimeout(ctx, 10*time.Second)
	defer dialCancel()

	conn, err := grpc.DialContext(dialCtx, processorAddr,
		grpc.WithTransportCredentials(creds),
		grpc.WithBlock(),
	)
	require.NoError(t, err, "Failed to dial TLS processor")
	defer conn.Close()

	// Wait a moment for the connection to be established
	time.Sleep(500 * time.Millisecond)

	dataClient := data.NewDataServiceClient(conn)
	mgmtClient := management.NewManagementServiceClient(conn)

	// Register hunter with a fresh context
	rpcCtx, rpcCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer rpcCancel()

	regResp, err := mgmtClient.RegisterHunter(rpcCtx, &management.HunterRegistration{
		HunterId:   "test-hunter-tls-mtls",
		Hostname:   "test-host-tls",
		Interfaces: []string{"mock0"},
		Version:    "test-1.0.0",
		Capabilities: &management.HunterCapabilities{
			FilterTypes:     []string{"bpf"},
			MaxBufferSize:   8192,
			GpuAcceleration: false,
			AfXdp:           false,
		},
	})
	require.NoError(t, err, "Failed to register hunter over TLS")
	assert.True(t, regResp.Accepted, "Hunter registration rejected over TLS")

	// Stream packets over TLS
	streamCtx, streamCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer streamCancel()

	stream, err := dataClient.StreamPackets(streamCtx)
	require.NoError(t, err, "Failed to create TLS stream")

	batch := &data.PacketBatch{
		HunterId:    "test-hunter-tls-mtls",
		Sequence:    1,
		TimestampNs: time.Now().UnixNano(),
		Packets:     convertToGrpcPackets(createTestPackets(10)),
		Stats: &data.BatchStats{
			TotalCaptured:   10,
			FilteredMatched: 0,
			Dropped:         0,
		},
	}

	err = stream.Send(batch)
	require.NoError(t, err, "Failed to send packet batch over TLS")

	// Receive acknowledgment
	resp, err := stream.Recv()
	require.NoError(t, err, "Failed to receive stream control over TLS")
	assert.NotNil(t, resp, "Stream control response is nil")

	// Verify processor received packets
	stats := proc.GetStats()
	assert.GreaterOrEqual(t, stats.TotalPacketsReceived, uint64(10), "Processor should have received packets over TLS")

	t.Logf("✓ TLS mutual auth test: Successfully exchanged packets over mTLS")
}

// TestIntegration_TLS_ClientAuthRequired tests that client certificates are required
func TestIntegration_TLS_ClientAuthRequired(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Load CA certificate
	certsDir := filepath.Join("testcerts")

	// Skip if certificates don't exist (not in integration test environment)
	if _, err := os.Stat(filepath.Join(certsDir, "ca-cert.pem")); os.IsNotExist(err) {
		t.Skip("Skipping TLS test: certificates not found (run in integration test environment with generated certs)")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	caCert, err := os.ReadFile(filepath.Join(certsDir, "ca-cert.pem"))
	require.NoError(t, err, "Failed to read CA certificate")

	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	// Start processor with TLS and client auth required
	processorAddr := "127.0.0.1:50059"
	proc, err := startTLSProcessor(t, ctx, processorAddr, certsDir, true)
	require.NoError(t, err, "Failed to start TLS processor")
	defer proc.Shutdown()

	// Wait for processor
	time.Sleep(500 * time.Millisecond)

	// Try to connect without client certificate (should fail)
	noClientCertTLSConfig := &tls.Config{
		MinVersion: tls.VersionTLS13,
		RootCAs:    caCertPool,
		ServerName: "processor.test.local",
		// No Certificates field - no client cert
	}

	creds := credentials.NewTLS(noClientCertTLSConfig)

	// Use a shorter timeout for connection attempts
	connCtx, connCancel := context.WithTimeout(ctx, 5*time.Second)
	defer connCancel()

	conn, err := grpc.DialContext(connCtx, processorAddr,
		grpc.WithTransportCredentials(creds),
		grpc.WithBlock(),
	)

	if err == nil {
		// If connection succeeds, try to make an RPC call - it should fail
		mgmtClient := management.NewManagementServiceClient(conn)
		_, rpcErr := mgmtClient.RegisterHunter(connCtx, &management.HunterRegistration{
			HunterId:   "test-hunter",
			Hostname:   "test-host",
			Interfaces: []string{"mock0"},
		})
		conn.Close()

		if rpcErr == nil {
			t.Fatal("Expected RPC to fail without client certificate, but it succeeded")
		}
		// The RPC error should indicate a TLS/certificate issue
		t.Logf("RPC failed as expected: %v", rpcErr)
	} else {
		// Connection failed as expected - this is the preferred outcome
		t.Logf("Connection failed as expected: %v", err)
	}

	t.Logf("✓ Client auth required test: Connection correctly rejected without client certificate")
}

// TestIntegration_TLS_TLS13Enforcement tests that TLS 1.3 is enforced
func TestIntegration_TLS_TLS13Enforcement(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	certsDir := filepath.Join("testcerts")

	// Skip if certificates don't exist (not in integration test environment)
	if _, err := os.Stat(filepath.Join(certsDir, "ca-cert.pem")); os.IsNotExist(err) {
		t.Skip("Skipping TLS test: certificates not found (run in integration test environment with generated certs)")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	caCert, err := os.ReadFile(filepath.Join(certsDir, "ca-cert.pem"))
	require.NoError(t, err)

	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	// Start processor with TLS 1.3
	processorAddr := "127.0.0.1:50060"
	proc, err := startTLSProcessor(t, ctx, processorAddr, certsDir, true)
	require.NoError(t, err)
	defer proc.Shutdown()

	time.Sleep(500 * time.Millisecond)

	// Load client certificate
	hunterCert, err := tls.LoadX509KeyPair(
		filepath.Join(certsDir, "hunter-cert.pem"),
		filepath.Join(certsDir, "hunter-key.pem"),
	)
	require.NoError(t, err)

	// Try to connect with TLS 1.2 (should be rejected)
	tls12Config := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS12, // Force TLS 1.2
		Certificates: []tls.Certificate{hunterCert},
		RootCAs:      caCertPool,
		ServerName:   "processor.test.local",
	}

	creds := credentials.NewTLS(tls12Config)

	connCtx, connCancel := context.WithTimeout(ctx, 5*time.Second)
	defer connCancel()

	conn, err := grpc.DialContext(connCtx, processorAddr,
		grpc.WithTransportCredentials(creds),
		grpc.WithBlock(),
	)

	if err == nil {
		// If connection succeeds, try an RPC - it should fail
		mgmtClient := management.NewManagementServiceClient(conn)
		_, rpcErr := mgmtClient.RegisterHunter(connCtx, &management.HunterRegistration{
			HunterId:   "test-hunter",
			Hostname:   "test-host",
			Interfaces: []string{"mock0"},
		})
		conn.Close()

		if rpcErr == nil {
			t.Fatal("Expected RPC to fail with TLS 1.2, but it succeeded")
		}
		t.Logf("RPC failed as expected: %v", rpcErr)
	} else {
		// Connection failed as expected
		t.Logf("Connection failed as expected: %v", err)
	}

	t.Logf("✓ TLS 1.3 enforcement test: TLS 1.2 correctly rejected")
}

// TestIntegration_TLS_InvalidCertificate tests rejection of invalid certificates
func TestIntegration_TLS_InvalidCertificate(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	certsDir := filepath.Join("testcerts")

	// Skip if certificates don't exist (not in integration test environment)
	if _, err := os.Stat(filepath.Join(certsDir, "ca-cert.pem")); os.IsNotExist(err) {
		t.Skip("Skipping TLS test: certificates not found (run in integration test environment with generated certs)")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Start processor with TLS
	processorAddr := "127.0.0.1:50061"
	proc, err := startTLSProcessor(t, ctx, processorAddr, certsDir, true)
	require.NoError(t, err)
	defer proc.Shutdown()

	time.Sleep(500 * time.Millisecond)

	// Try to connect with self-signed cert (not signed by our CA)
	selfSignedCert, err := tls.X509KeyPair([]byte(selfSignedCertPEM), []byte(selfSignedKeyPEM))
	require.NoError(t, err)

	// Load CA for server verification
	caCert, err := os.ReadFile(filepath.Join(certsDir, "ca-cert.pem"))
	require.NoError(t, err)
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	invalidCertConfig := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{selfSignedCert},
		RootCAs:      caCertPool,
		ServerName:   "processor.test.local",
	}

	creds := credentials.NewTLS(invalidCertConfig)

	connCtx, connCancel := context.WithTimeout(ctx, 5*time.Second)
	defer connCancel()

	conn, err := grpc.DialContext(connCtx, processorAddr,
		grpc.WithTransportCredentials(creds),
		grpc.WithBlock(),
	)

	if err == nil {
		// If connection succeeds, try an RPC - it should fail
		mgmtClient := management.NewManagementServiceClient(conn)
		_, rpcErr := mgmtClient.RegisterHunter(connCtx, &management.HunterRegistration{
			HunterId:   "test-hunter",
			Hostname:   "test-host",
			Interfaces: []string{"mock0"},
		})
		conn.Close()

		if rpcErr == nil {
			t.Fatal("Expected RPC to fail with invalid certificate, but it succeeded")
		}
		t.Logf("RPC failed as expected: %v", rpcErr)
	} else {
		// Connection failed as expected
		t.Logf("Connection failed as expected: %v", err)
	}

	t.Logf("✓ Invalid certificate test: Invalid client certificate correctly rejected")
}

// TestIntegration_TLS_ServerNameVerification tests server name verification
func TestIntegration_TLS_ServerNameVerification(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	certsDir := filepath.Join("testcerts")

	// Skip if certificates don't exist (not in integration test environment)
	if _, err := os.Stat(filepath.Join(certsDir, "ca-cert.pem")); os.IsNotExist(err) {
		t.Skip("Skipping TLS test: certificates not found (run in integration test environment with generated certs)")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	caCert, err := os.ReadFile(filepath.Join(certsDir, "ca-cert.pem"))
	require.NoError(t, err)

	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	// Start processor
	processorAddr := "127.0.0.1:50062"
	proc, err := startTLSProcessor(t, ctx, processorAddr, certsDir, true)
	require.NoError(t, err)
	defer proc.Shutdown()

	time.Sleep(500 * time.Millisecond)

	// Load client certificate
	hunterCert, err := tls.LoadX509KeyPair(
		filepath.Join(certsDir, "hunter-cert.pem"),
		filepath.Join(certsDir, "hunter-key.pem"),
	)
	require.NoError(t, err)

	// Try to connect with wrong ServerName
	wrongServerNameConfig := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{hunterCert},
		RootCAs:      caCertPool,
		ServerName:   "wrong.server.name", // Wrong name
	}

	creds := credentials.NewTLS(wrongServerNameConfig)

	connCtx, connCancel := context.WithTimeout(ctx, 5*time.Second)
	defer connCancel()

	conn, err := grpc.DialContext(connCtx, processorAddr,
		grpc.WithTransportCredentials(creds),
		grpc.WithBlock(),
	)

	if err == nil {
		// If connection succeeds, try an RPC - it should fail
		mgmtClient := management.NewManagementServiceClient(conn)
		_, rpcErr := mgmtClient.RegisterHunter(connCtx, &management.HunterRegistration{
			HunterId:   "test-hunter",
			Hostname:   "test-host",
			Interfaces: []string{"mock0"},
		})
		conn.Close()

		if rpcErr == nil {
			t.Fatal("Expected RPC to fail with wrong server name, but it succeeded")
		}
		t.Logf("RPC failed as expected: %v", rpcErr)
	} else {
		// Connection failed as expected - this is the preferred outcome
		t.Logf("Connection failed as expected: %v", err)
	}

	t.Logf("✓ Server name verification test: Wrong ServerName correctly rejected")
}

// TestIntegration_TLS_ProductionModeEnforcement tests production mode enforcement
func TestIntegration_TLS_ProductionModeEnforcement(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	certsDir := filepath.Join("testcerts")

	// Skip if certificates don't exist (not in integration test environment)
	if _, err := os.Stat(filepath.Join(certsDir, "ca-cert.pem")); os.IsNotExist(err) {
		t.Skip("Skipping TLS test: certificates not found (run in integration test environment with generated certs)")
	}

	// Set production mode
	originalValue := os.Getenv("LIPPYCAT_PRODUCTION")
	os.Setenv("LIPPYCAT_PRODUCTION", "true")
	defer os.Setenv("LIPPYCAT_PRODUCTION", originalValue)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Try to start processor without TLS in production mode
	processorAddr := "127.0.0.1:50063"
	config := &processor.Config{
		ListenAddr:     processorAddr,
		TLSEnabled:     false, // Insecure in production
		MaxHunters:     10,
		MaxSubscribers: 5,
		FilterFile:     "/tmp/lippycat-test-filters-does-not-exist.yaml", // Non-existent path to start with clean filter state
	}

	proc, err := processor.New(*config)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}
	err = proc.Start(ctx)

	// Should fail in production mode without TLS
	if err == nil {
		proc.Shutdown()
		t.Fatal("Expected processor to fail without TLS in production mode")
	}

	assert.Contains(t, err.Error(), "LIPPYCAT_PRODUCTION", "Error should mention production mode")

	t.Logf("✓ Production mode enforcement test: Insecure config correctly rejected")
}

// Helper function to start a TLS-enabled processor
// Uses t.TempDir() for filter file to ensure test isolation
func startTLSProcessor(t *testing.T, ctx context.Context, addr, certsDir string, requireClientAuth bool) (*processor.Processor, error) {
	serverCert := filepath.Join(certsDir, "processor-cert.pem")
	serverKey := filepath.Join(certsDir, "processor-key.pem")
	caCert := filepath.Join(certsDir, "ca-cert.pem")

	// Use t.TempDir() for filter file to ensure each test has isolated state
	filterFile := filepath.Join(t.TempDir(), "filters.yaml")

	config := &processor.Config{
		ListenAddr:     addr,
		TLSEnabled:     true,
		TLSCertFile:    serverCert,
		TLSKeyFile:     serverKey,
		TLSCAFile:      caCert,
		TLSClientAuth:  requireClientAuth,
		MaxHunters:     10,
		MaxSubscribers: 5,
		FilterFile:     filterFile,
	}

	proc, err := processor.New(*config)
	if err != nil {
		return nil, err
	}

	// Start processor in background
	go func() {
		if err := proc.Start(ctx); err != nil {
			// Processor stopped with error (non-fatal for tests)
			// The test will handle any connection errors
		}
	}()

	// Give processor time to start listening
	// CI with race detector needs more time
	time.Sleep(2 * time.Second)

	return proc, nil
}

// Self-signed certificate for testing invalid cert scenarios
// This certificate is NOT signed by the test CA, so it should be rejected
const selfSignedCertPEM = `-----BEGIN CERTIFICATE-----
MIIDoTCCAomgAwIBAgIUTkdncBhrTk890rcDdVPB5Bghi+swDQYJKoZIhvcNAQEL
BQAwYDELMAkGA1UEBhMCVVMxEDAOBgNVBAgMB0ludmFsaWQxEDAOBgNVBAcMB0lu
dmFsaWQxEDAOBgNVBAoMB0ludmFsaWQxGzAZBgNVBAMMEmludmFsaWQudGVzdC5s
b2NhbDAeFw0yNTEwMTAxODM5MzJaFw0yNjEwMTAxODM5MzJaMGAxCzAJBgNVBAYT
AlVTMRAwDgYDVQQIDAdJbnZhbGlkMRAwDgYDVQQHDAdJbnZhbGlkMRAwDgYDVQQK
DAdJbnZhbGlkMRswGQYDVQQDDBJpbnZhbGlkLnRlc3QubG9jYWwwggEiMA0GCSqG
SIb3DQEBAQUAA4IBDwAwggEKAoIBAQC9koGM8FG3qLcHxQ4IkjrUytOgQxVqYldO
P146xSXxzHRE0HyMYTi2mGofIfcR1gXBgP62ZFubccL2m2ZuLqtYjB6cqKS2ZM7Z
Q4AK8CF1D8R2DOqLzKuR7Qbn6C4CUQZb/8Tc71kiKFUFkOQH2lYMLkAHkLSskDw7
g3HTPPWL/hslzkjnVbXfTz+rNy5YHKZ9gFQmbJKCrFmwjd/n4MIMfqDCKPr3EbQK
d5bY1NjbJBDrwFSiuvqhHWTVyjpnDG2ZeKzWi7w9KQSUHWypcH1+qpCqdwszyrrO
PhVogLRWhuu1pi1908KCToI0gSttbYHnzrs51bLJwc/XxmSrdygXAgMBAAGjUzBR
MB0GA1UdDgQWBBSQUL7LBBKVP7QBe+lQYmmLZ2VwATAfBgNVHSMEGDAWgBSQUL7L
BBKVP7QBe+lQYmmLZ2VwATAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUA
A4IBAQAFaV3ue12HkBcilv/SnzwxXKGUfZ0KcHmj6BIKmtlus8LD9+hnfZHu/ics
v9LZQWLe6Etvb2qoCDGIorX2P5Ytf2sn1wq5cNnTi/pSDj8GuklD59+zmMu687T7
1Efc5AaEc35uFvucfC0v6upNQLdGwOb7NolfWbe9WKll7+NsCtOksO66yR3lqmzR
3s0HavPoSEEApaGnnX0a863OhwUEoY5dyzYuc1kwlZGq8tbE09s4mpfaphu/91ky
dH50JDZh6Zfvm8/0Wsg990av+AwvVXSEXwDVDgvscU6qT7jl4yqSeLnMyBRcZp/8
WPBJ9IYGNM1GtPTX2r1QsX62rfQ/
-----END CERTIFICATE-----`

const selfSignedKeyPEM = `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC9koGM8FG3qLcH
xQ4IkjrUytOgQxVqYldOP146xSXxzHRE0HyMYTi2mGofIfcR1gXBgP62ZFubccL2
m2ZuLqtYjB6cqKS2ZM7ZQ4AK8CF1D8R2DOqLzKuR7Qbn6C4CUQZb/8Tc71kiKFUF
kOQH2lYMLkAHkLSskDw7g3HTPPWL/hslzkjnVbXfTz+rNy5YHKZ9gFQmbJKCrFmw
jd/n4MIMfqDCKPr3EbQKd5bY1NjbJBDrwFSiuvqhHWTVyjpnDG2ZeKzWi7w9KQSU
HWypcH1+qpCqdwszyrrOPhVogLRWhuu1pi1908KCToI0gSttbYHnzrs51bLJwc/X
xmSrdygXAgMBAAECggEABkD5CR88cuSb9SOpDNtWGYL/bEAKStInsysf/qxWTh3C
kCqYkUD7z/pDNfe24N3AntuUi4vQAdbE6cHCpUvg1zD4KY7esC2vLTeu162ITQZS
ItrWOfpshondOnVMX0MxBIPxiKBUvm26ME7RVvj68bfs4NMDQtYXRpdVf/R43T9c
N03psEOde4ZP0Ge32oYpjpoOyx3dujLMpECy4i6Rg4+TJeSJtUhvdeuY0UCTpBKD
euSrxGQd3R9zVxAY3yNZbpY77ac0MgigAKbJfZ+t2C9SSyKxk7SLzqP8Q9fru9Je
b9miYoALSoqWuQ+nvjap2Xv9CuNBGwuIs+yreVlyYQKBgQDi+uXQABOEL+1vJGut
b7N569eCLKn9Sq/XtIuSpTl93ppygLrBvr/VexRQ+aZK9hWO4+CXnGAEJ0lQKCPz
MyGwBBIpNi05vxUGzqH4bMW/7ZMfKL0x6BLqDzAQqCGuWnGXFs3qwIPC4kOQf3fr
Ralpl1UyGMy7x8Au0oE9lqgJqQKBgQDVzz6Obsz/0YIZnkuXYHm94nW9O8EP4fWK
YqESbN8w+1H67d7+++oOHkzsuk9dvm/knf+hbZ8i2dIhpHryv9mfR0pFl/JNTHxs
c3MmCdl04TwX734WHFcDwihvVvccRqs0n8iaWJ050CGHat4N9yuTrczVR9aGAqQd
pp4H0a47vwKBgQDgQuUtTeX6hSAi3+lDw0mg/NRBWb/a8yAqD8iXa4gSRQ50c5wS
MVV4p9K67u7OwbUrKRuOsIJtmCNnf0GF2M9ACcWn0k987r7nquF9gnsf1qu17ZqA
5LtLZxYmXvhoPBRfI7jwaKXGt6fp7Qee/YUVPuB+TuJ55jKMEJCBOYltgQKBgAUv
GjAv5Y6KUOI4IVMRRsJg3EPzT/IHo4FwdMFSnHK+lTVFUTPTfdBL0cenmMcIGARu
BEWwt7wLlfm02DpMhoVDIDzhu0E+ioHCptcURA5+a4uVBfSZSU7RBVP1wtYPrJUB
DscXQPCm6Dk1UR77kDXrb9z3+e6T39DMOmasIdJXAoGAXNqD65O79uSIbyDzKhbm
YJslF69yijRb/TqvEUtM0A9/mdSMmbRXKTf+g+ToYHrLDDhg/3LJ8r5FhEIerkD3
QZ2WDtgyO+AvmldQhOzDGCBvyKQBSiNVQsFSY2BsKK2B2BdKzqBvjajy1vZe845b
GM/0duj+cC3HmKwebcBComc=
-----END PRIVATE KEY-----`
