package test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
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

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Load test certificates
	certsDir := filepath.Join("testcerts")
	caCert, err := os.ReadFile(filepath.Join(certsDir, "ca-cert.pem"))
	require.NoError(t, err, "Failed to read CA certificate")

	caCertPool := x509.NewCertPool()
	ok := caCertPool.AppendCertsFromPEM(caCert)
	require.True(t, ok, "Failed to parse CA certificate")

	// Start processor with TLS enabled
	processorAddr := "127.0.0.1:50058"
	proc, err := startTLSProcessor(ctx, processorAddr, certsDir, true)
	require.NoError(t, err, "Failed to start TLS processor")
	defer proc.Shutdown()

	// Wait for processor to be ready
	time.Sleep(500 * time.Millisecond)

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
	conn, err := grpc.DialContext(ctx, processorAddr,
		grpc.WithTransportCredentials(creds),
		grpc.WithBlock(),
	)
	require.NoError(t, err, "Failed to connect to TLS processor")
	defer conn.Close()

	dataClient := data.NewDataServiceClient(conn)
	mgmtClient := management.NewManagementServiceClient(conn)

	// Register hunter
	regResp, err := mgmtClient.RegisterHunter(ctx, &management.HunterRegistration{
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
	stream, err := dataClient.StreamPackets(ctx)
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

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Load CA certificate
	certsDir := filepath.Join("testcerts")
	caCert, err := os.ReadFile(filepath.Join(certsDir, "ca-cert.pem"))
	require.NoError(t, err, "Failed to read CA certificate")

	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	// Start processor with TLS and client auth required
	processorAddr := "127.0.0.1:50059"
	proc, err := startTLSProcessor(ctx, processorAddr, certsDir, true)
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
	conn, err := grpc.DialContext(ctx, processorAddr,
		grpc.WithTransportCredentials(creds),
		grpc.WithBlock(),
		grpc.WithTimeout(5*time.Second),
	)

	if err == nil {
		conn.Close()
		t.Fatal("Expected connection to fail without client certificate, but it succeeded")
	}

	// Verify the error is related to client certificate
	assert.Contains(t, err.Error(), "certificate", "Error should mention certificate issue")

	t.Logf("✓ Client auth required test: Connection correctly rejected without client certificate")
}

// TestIntegration_TLS_TLS13Enforcement tests that TLS 1.3 is enforced
func TestIntegration_TLS_TLS13Enforcement(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	certsDir := filepath.Join("testcerts")
	caCert, err := os.ReadFile(filepath.Join(certsDir, "ca-cert.pem"))
	require.NoError(t, err)

	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	// Start processor with TLS 1.3
	processorAddr := "127.0.0.1:50060"
	proc, err := startTLSProcessor(ctx, processorAddr, certsDir, true)
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
	conn, err := grpc.DialContext(ctx, processorAddr,
		grpc.WithTransportCredentials(creds),
		grpc.WithBlock(),
		grpc.WithTimeout(5*time.Second),
	)

	if err == nil {
		conn.Close()
		t.Fatal("Expected connection to fail with TLS 1.2, but it succeeded")
	}

	// Verify TLS version error
	assert.Contains(t, err.Error(), "protocol version", "Error should mention protocol version")

	t.Logf("✓ TLS 1.3 enforcement test: TLS 1.2 correctly rejected")
}

// TestIntegration_TLS_InvalidCertificate tests rejection of invalid certificates
func TestIntegration_TLS_InvalidCertificate(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	certsDir := filepath.Join("testcerts")

	// Start processor with TLS
	processorAddr := "127.0.0.1:50061"
	proc, err := startTLSProcessor(ctx, processorAddr, certsDir, true)
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
	conn, err := grpc.DialContext(ctx, processorAddr,
		grpc.WithTransportCredentials(creds),
		grpc.WithBlock(),
		grpc.WithTimeout(5*time.Second),
	)

	if err == nil {
		conn.Close()
		t.Fatal("Expected connection to fail with invalid certificate, but it succeeded")
	}

	assert.Contains(t, err.Error(), "certificate", "Error should mention certificate issue")

	t.Logf("✓ Invalid certificate test: Invalid client certificate correctly rejected")
}

// TestIntegration_TLS_ServerNameVerification tests server name verification
func TestIntegration_TLS_ServerNameVerification(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	certsDir := filepath.Join("testcerts")
	caCert, err := os.ReadFile(filepath.Join(certsDir, "ca-cert.pem"))
	require.NoError(t, err)

	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	// Start processor
	processorAddr := "127.0.0.1:50062"
	proc, err := startTLSProcessor(ctx, processorAddr, certsDir, true)
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
	conn, err := grpc.DialContext(ctx, processorAddr,
		grpc.WithTransportCredentials(creds),
		grpc.WithBlock(),
		grpc.WithTimeout(5*time.Second),
	)

	if err == nil {
		conn.Close()
		t.Fatal("Expected connection to fail with wrong server name, but it succeeded")
	}

	assert.Contains(t, err.Error(), "certificate", "Error should mention certificate verification issue")

	t.Logf("✓ Server name verification test: Wrong ServerName correctly rejected")
}

// TestIntegration_TLS_ProductionModeEnforcement tests production mode enforcement
func TestIntegration_TLS_ProductionModeEnforcement(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
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
		ListenAddr:       processorAddr,
		TLSEnabled:       false, // Insecure in production
		MaxHunters:       10,
		MaxSubscribers:   5,
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
func startTLSProcessor(ctx context.Context, addr, certsDir string, requireClientAuth bool) (*processor.Processor, error) {
	serverCert := filepath.Join(certsDir, "processor-cert.pem")
	serverKey := filepath.Join(certsDir, "processor-key.pem")
	caCert := filepath.Join(certsDir, "ca-cert.pem")

	config := &processor.Config{
		ListenAddr:       addr,
		TLSEnabled:       true,
		TLSCertFile:      serverCert,
		TLSKeyFile:       serverKey,
		TLSCAFile:        caCert,
		TLSClientAuth:    requireClientAuth,
		MaxHunters:       10,
		MaxSubscribers:   5,
	}

	proc, err := processor.New(*config)
	if err != nil {
		return nil, err
	}
	if err := proc.Start(ctx); err != nil {
		return nil, fmt.Errorf("failed to start processor: %w", err)
	}

	return proc, nil
}

// Self-signed certificate for testing invalid cert scenarios
const selfSignedCertPEM = `-----BEGIN CERTIFICATE-----
MIIDazCCAlOgAwIBAgIUXMH1VPGLvvT1EEGd6Z1LqYKRp4kwDQYJKoZIhvcNAQEL
BQAwRTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoM
GEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAeFw0yNTAxMDEwMDAwMDBaFw0yNjAx
MDEwMDAwMDBaMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEw
HwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQC7VJTUt9Us8cKjMzEfYyjiWA4/qMD/Cw1YCM7n2L0D
0QZwi/HM2Fudc4tQ1ocChBnZlMWdX3KGVmj5w9YtYlBf47OqKTHLyXYTzKK3fkCd
w1iZ2l2aFqTGDJThcJvlGRmQzSGN1BfhX3iGp9qE4b2h3sj2FGHUoKnI4pP0k5sJ
g9UxSxYiE0fJ7ixVG8qFZoKWQ6tGLbnLwhGN1vGDLHMEq8nCfTF3zd3bNGDELLjh
VQUKqJl8nOQvGHJmDnLvEyJVhYT5YhjZdJjI+iBEq+NpLKjRJ8BF3LdC3JzCpZHV
AqJmCfWdL9JTHpJ9l4KpJ2m0OEqMqq3MR4pLjQqPq4J7AgMBAAGjUzBRMB0GA1Ud
DgQWBBSbXlPqDJcGQ3F5x+7hB3cF8L0+gjAfBgNVHSMEGDAWgBSbXlPqDJcGQ3F5
x+7hB3cF8L0+gjAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQBe
kZx2Dx2PqH8wvvXfJBqYkLslLCZvlEi0X8WpNAlKs5cJTmJbVbwPqJaJl5LKy7KJ
nk5i3qTi1L8+aBsKpkJNdKYZLlFJKsKdSxGBFJJtKp7YUxlNh6v5J5TqS8x0rjBb
HuVp1bLV4GW2N3Kj7LdPpLqLt6L0wOE8l7L9xFaI5VT0P5+6QPlKIk9LqvQlj1VY
QFNqWpLqhJLZsKX7LiJbYlQqL8pL1b6L1QHLsL8JqLkpLvLsL9L0LqL3L4L5L6L7
L8L9LqL1L2L3L4L5L6L7L8L9L0L1L2L3L4L5L6L7L8L9L0L1L2L3L4L5L6L7L8L9
-----END CERTIFICATE-----`

const selfSignedKeyPEM = `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKj
MzEfYyjiWA4/qMD/Cw1YCM7n2L0D0QZwi/HM2Fudc4tQ1ocChBnZlMWdX3KGVmj5
w9YtYlBf47OqKTHLyXYTzKK3fkCdw1iZ2l2aFqTGDJThcJvlGRmQzSGN1BfhX3iG
p9qE4b2h3sj2FGHUoKnI4pP0k5sJg9UxSxYiE0fJ7ixVG8qFZoKWQ6tGLbnLwhGN
1vGDLHMEq8nCfTF3zd3bNGDELLjhVQUKqJl8nOQvGHJmDnLvEyJVhYT5YhjZdJjI
+iBEq+NpLKjRJ8BF3LdC3JzCpZHVAqJmCfWdL9JTHpJ9l4KpJ2m0OEqMqq3MR4pL
jQqPq4J7AgMBAAECggEAAJ3SBgKoNZaOCJx/nVsWU1C4VnGp6Z9RpCPx0XgQvQH8
lOzCQEJ7vKb9L8h3i8bLPZVqL4J5L6J7L8J9LqJ1L2J3L4J5L6J7L8J9J0J1J2J3
J4J5J6J7J8J9J0J1J2J3J4J5J6J7J8J9J0J1J2J3J4J5J6J7J8J9J0J1J2J3J4J5
J6J7J8J9J0J1J2J3J4J5J6J7J8J9J0J1J2J3J4J5J6J7J8J9J0J1J2J3J4J5J6J7
J8J9J0J1J2J3J4J5J6J7J8J9J0J1J2J3J4J5J6J7J8J9J0J1J2J3J4J5J6J7J8J9
J0J1J2J3J4J5J6J7J8J9J0J1J2J3J4J5J6J7J8J9J0J1J2J3J4J5J6J7J8J9JQsK
BgQDlJqZ5J6l7J8l9JqlqJ2l3J4l5J6l7J8l9l0l1l2l3l4l5l6l7l8l9l0l1l2l3
l4l5l6l7l8l9l0l1l2l3l4l5l6l7l8l9l0l1l2l3l4l5l6l7l8l9l0l1l2l3l4l5
l6l7l8l9l0l1l2l3l4l5l6l7l8l9lQsKBgQDQJpZ6J7l8J9JqlqJ2l3J4l5J6l7J8
l9l0l1l2l3l4l5l6l7l8l9l0l1l2l3l4l5l6l7l8l9l0l1l2l3l4l5l6l7l8l9l0
l1l2l3l4l5l6l7l8l9l0l1l2l3l4l5l6l7l8l9l0l1l2l3l4l5l6l7l8l9lQsKBg
-----END PRIVATE KEY-----`
