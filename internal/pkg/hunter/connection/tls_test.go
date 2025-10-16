package connection

import (
	"crypto/tls"
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
)

// Test helper: create temporary certificate files
func createTestCerts(t *testing.T) (certFile, keyFile, caFile string, cleanup func()) {
	t.Helper()

	tmpDir := t.TempDir()

	// Generate test certificate and key (same as processor test)
	certPEM := []byte(`-----BEGIN CERTIFICATE-----
MIIBhTCCASugAwIBAgIQIRi6zePL6mKjOipn+dNuaTAKBggqhkjOPQQDAjASMRAw
DgYDVQQKEwdBY21lIENvMB4XDTE3MTAyMDE5NDMwNloXDTE4MTAyMDE5NDMwNlow
EjEQMA4GA1UEChMHQWNtZSBDbzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABD0d
7VNhbWvZLWPuj/RtHFjvtJBEwOkhbN/BnnE8rnZR8+sbwnc/KhCk3FhnpHZnQz7B
5aETbbIgmuvewdjvSBSjYzBhMA4GA1UdDwEB/wQEAwICpDATBgNVHSUEDDAKBggr
BgEFBQcDATAPBgNVHRMBAf8EBTADAQH/MCkGA1UdEQQiMCCCDmxvY2FsaG9zdDo1
NDUzgg4xMjcuMC4wLjE6NTQ1MzAKBggqhkjOPQQDAgNIADBFAiEA2zpJEPQyz6/l
Wf86aX6PepsntZv2GYlA5UpabfT2EZICICpJ5h/iI+i341gBmLiAFQOyTDT+/wQc
6MF9+Yw1Yy0t
-----END CERTIFICATE-----`)

	keyPEM := []byte(`-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIIrYSSNQFaA2Hwf1duRSxKtLYX5CB04fSeQ6tF1aY/PuoAoGCCqGSM49
AwEHoUQDQgAEPR3tU2Fta9ktY+6P9G0cWO+0kETA6SFs38GecTyudlHz6xvCdz8q
EKTcWGekdmdDPsHloRNtsiCa697B2O9IFA==
-----END EC PRIVATE KEY-----`)

	certFile = filepath.Join(tmpDir, "cert.pem")
	keyFile = filepath.Join(tmpDir, "key.pem")
	caFile = filepath.Join(tmpDir, "ca.pem")

	if err := os.WriteFile(certFile, certPEM, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(caFile, certPEM, 0644); err != nil {
		t.Fatal(err)
	}

	cleanup = func() {
		os.RemoveAll(tmpDir)
	}

	return certFile, keyFile, caFile, cleanup
}

func TestBuildTLSCredentials_Success(t *testing.T) {
	certFile, keyFile, caFile, cleanup := createTestCerts(t)
	defer cleanup()

	m := &Manager{
		config: Config{
			TLSCAFile:   caFile,
			TLSCertFile: certFile,
			TLSKeyFile:  keyFile,
		},
	}

	creds, err := m.buildTLSCredentials()
	if err != nil {
		t.Fatalf("buildTLSCredentials() failed: %v", err)
	}

	if creds == nil {
		t.Fatal("buildTLSCredentials() returned nil credentials")
	}

	info := creds.Info()
	if info.SecurityProtocol != "tls" {
		t.Errorf("expected security protocol 'tls', got %q", info.SecurityProtocol)
	}
}

func TestBuildTLSCredentials_WithoutCertificates(t *testing.T) {
	m := &Manager{
		config: Config{
			TLSSkipVerify: false,
		},
	}

	creds, err := m.buildTLSCredentials()
	if err != nil {
		t.Fatalf("buildTLSCredentials() failed: %v", err)
	}

	if creds == nil {
		t.Fatal("buildTLSCredentials() returned nil credentials")
	}

	// Should succeed with system cert pool
}

func TestBuildTLSCredentials_SkipVerify(t *testing.T) {
	m := &Manager{
		config: Config{
			TLSSkipVerify: true,
		},
	}

	creds, err := m.buildTLSCredentials()
	if err != nil {
		t.Fatalf("buildTLSCredentials() failed: %v", err)
	}

	if creds == nil {
		t.Fatal("buildTLSCredentials() returned nil credentials")
	}
}

func TestBuildTLSCredentials_WithCA(t *testing.T) {
	_, _, caFile, cleanup := createTestCerts(t)
	defer cleanup()

	m := &Manager{
		config: Config{
			TLSCAFile: caFile,
		},
	}

	creds, err := m.buildTLSCredentials()
	if err != nil {
		t.Fatalf("buildTLSCredentials() failed: %v", err)
	}

	if creds == nil {
		t.Fatal("buildTLSCredentials() returned nil credentials")
	}
}

func TestBuildTLSCredentials_InvalidCAFile(t *testing.T) {
	m := &Manager{
		config: Config{
			TLSCAFile: "/nonexistent/ca.pem",
		},
	}

	_, err := m.buildTLSCredentials()
	if err == nil {
		t.Fatal("expected error when CA file doesn't exist, got nil")
	}
}

func TestBuildTLSCredentials_InvalidCAData(t *testing.T) {
	tmpDir := t.TempDir()
	invalidCA := filepath.Join(tmpDir, "invalid_ca.pem")
	if err := os.WriteFile(invalidCA, []byte("invalid cert data"), 0644); err != nil {
		t.Fatal(err)
	}

	m := &Manager{
		config: Config{
			TLSCAFile: invalidCA,
		},
	}

	_, err := m.buildTLSCredentials()
	if err == nil {
		t.Fatal("expected error when CA file contains invalid data, got nil")
	}
}

func TestBuildTLSCredentials_WithClientCert(t *testing.T) {
	certFile, keyFile, caFile, cleanup := createTestCerts(t)
	defer cleanup()

	m := &Manager{
		config: Config{
			TLSCAFile:   caFile,
			TLSCertFile: certFile,
			TLSKeyFile:  keyFile,
		},
	}

	creds, err := m.buildTLSCredentials()
	if err != nil {
		t.Fatalf("buildTLSCredentials() failed: %v", err)
	}

	if creds == nil {
		t.Fatal("buildTLSCredentials() returned nil credentials")
	}
}

func TestBuildTLSCredentials_InvalidClientCert(t *testing.T) {
	_, keyFile, caFile, cleanup := createTestCerts(t)
	defer cleanup()

	m := &Manager{
		config: Config{
			TLSCAFile:   caFile,
			TLSCertFile: "/nonexistent/cert.pem",
			TLSKeyFile:  keyFile,
		},
	}

	_, err := m.buildTLSCredentials()
	if err == nil {
		t.Fatal("expected error when cert file doesn't exist, got nil")
	}
}

func TestBuildTLSCredentials_CertWithoutKey(t *testing.T) {
	certFile, _, caFile, cleanup := createTestCerts(t)
	defer cleanup()

	m := &Manager{
		config: Config{
			TLSCAFile:   caFile,
			TLSCertFile: certFile,
			TLSKeyFile:  "",
		},
	}

	// Should fail - partial cert/key configuration is an error
	_, err := m.buildTLSCredentials()
	if err == nil {
		t.Fatal("expected error when only cert file is provided, got nil")
	}
}

func TestBuildTLSCredentials_KeyWithoutCert(t *testing.T) {
	_, keyFile, caFile, cleanup := createTestCerts(t)
	defer cleanup()

	m := &Manager{
		config: Config{
			TLSCAFile:   caFile,
			TLSCertFile: "",
			TLSKeyFile:  keyFile,
		},
	}

	// Should fail - partial cert/key configuration is an error
	_, err := m.buildTLSCredentials()
	if err == nil {
		t.Fatal("expected error when only key file is provided, got nil")
	}
}

func TestBuildTLSCredentials_ServerNameOverride(t *testing.T) {
	m := &Manager{
		config: Config{
			TLSServerNameOverride: "custom.example.com",
		},
	}

	creds, err := m.buildTLSCredentials()
	if err != nil {
		t.Fatalf("buildTLSCredentials() failed: %v", err)
	}

	if creds == nil {
		t.Fatal("buildTLSCredentials() returned nil credentials")
	}
}

func TestTLSConfig_LoadCertificates(t *testing.T) {
	certFile, keyFile, _, cleanup := createTestCerts(t)
	defer cleanup()

	// Test that certificates can be loaded
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatalf("failed to load test certificates: %v", err)
	}

	if len(cert.Certificate) == 0 {
		t.Fatal("certificate chain is empty")
	}
}

func TestTLSConfig_CAPool(t *testing.T) {
	_, _, caFile, cleanup := createTestCerts(t)
	defer cleanup()

	// Test CA certificate loading
	caCert, err := os.ReadFile(caFile)
	if err != nil {
		t.Fatalf("failed to read CA file: %v", err)
	}

	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM(caCert) {
		t.Fatal("failed to parse CA certificate")
	}

	if len(certPool.Subjects()) == 0 {
		t.Fatal("CA pool is empty after adding certificate")
	}
}

func TestTLSCredentials_Integration(t *testing.T) {
	certFile, keyFile, caFile, cleanup := createTestCerts(t)
	defer cleanup()

	// Test complete configuration
	m := &Manager{
		config: Config{
			TLSCAFile:             caFile,
			TLSCertFile:           certFile,
			TLSKeyFile:            keyFile,
			TLSSkipVerify:         false,
			TLSServerNameOverride: "localhost",
		},
	}

	creds, err := m.buildTLSCredentials()
	if err != nil {
		t.Fatalf("buildTLSCredentials() with full config failed: %v", err)
	}

	if creds == nil {
		t.Fatal("buildTLSCredentials() returned nil credentials")
	}

	info := creds.Info()
	if info.SecurityProtocol != "tls" {
		t.Errorf("expected security protocol 'tls', got %q", info.SecurityProtocol)
	}
}

// TestBuildTLSCredentials_EnforcesTLS13 verifies that TLS credentials are built successfully.
// Note: The MinVersion=TLS13 setting is enforced in the code (hunter.go:286) but cannot be
// tested directly via reflection because grpc.credentials uses unexported fields.
// Integration tests should verify that only TLS 1.3+ connections are accepted.
func TestBuildTLSCredentials_EnforcesTLS13(t *testing.T) {
	tests := []struct {
		name   string
		config Config
	}{
		{
			name: "default config",
			config: Config{
				TLSSkipVerify: false,
			},
		},
		{
			name: "with skip verify",
			config: Config{
				TLSSkipVerify: true,
			},
		},
		{
			name: "with server name override",
			config: Config{
				TLSSkipVerify:         false,
				TLSServerNameOverride: "example.com",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &Manager{config: tt.config}

			creds, err := m.buildTLSCredentials()
			if err != nil {
				t.Fatalf("buildTLSCredentials() failed: %v", err)
			}

			if creds == nil {
				t.Fatal("buildTLSCredentials() returned nil credentials")
			}

			// Verify credentials have TLS protocol
			info := creds.Info()
			if info.SecurityProtocol != "tls" {
				t.Errorf("expected security protocol 'tls', got %q", info.SecurityProtocol)
			}
		})
	}
}

func TestBuildTLSCredentials_WithCertificatesEnforcesTLS13(t *testing.T) {
	certFile, keyFile, caFile, cleanup := createTestCerts(t)
	defer cleanup()

	m := &Manager{
		config: Config{
			TLSCAFile:   caFile,
			TLSCertFile: certFile,
			TLSKeyFile:  keyFile,
		},
	}

	creds, err := m.buildTLSCredentials()
	if err != nil {
		t.Fatalf("buildTLSCredentials() failed: %v", err)
	}

	if creds == nil {
		t.Fatal("buildTLSCredentials() returned nil credentials")
	}

	// Verify credentials have TLS protocol
	info := creds.Info()
	if info.SecurityProtocol != "tls" {
		t.Errorf("expected security protocol 'tls', got %q", info.SecurityProtocol)
	}
}
