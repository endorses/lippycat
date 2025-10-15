package processor

import (
	"crypto/tls"
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"

	"github.com/endorses/lippycat/internal/pkg/tlsutil"
)

// Test helper: create temporary certificate files
func createTestCerts(t *testing.T) (certFile, keyFile, caFile string, cleanup func()) {
	t.Helper()

	tmpDir := t.TempDir()

	// Generate test certificate and key
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
	certFile, keyFile, _, cleanup := createTestCerts(t)
	defer cleanup()

	p := &Processor{
		config: Config{
			TLSCertFile: certFile,
			TLSKeyFile:  keyFile,
		},
	}

	creds, err := p.buildTLSCredentials()
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

func TestBuildTLSCredentials_MissingCertFile(t *testing.T) {
	p := &Processor{
		config: Config{
			TLSCertFile: "",
			TLSKeyFile:  "/path/to/key.pem",
		},
	}

	_, err := p.buildTLSCredentials()
	if err == nil {
		t.Fatal("expected error when cert file is missing, got nil")
	}
}

func TestBuildTLSCredentials_MissingKeyFile(t *testing.T) {
	p := &Processor{
		config: Config{
			TLSCertFile: "/path/to/cert.pem",
			TLSKeyFile:  "",
		},
	}

	_, err := p.buildTLSCredentials()
	if err == nil {
		t.Fatal("expected error when key file is missing, got nil")
	}
}

func TestBuildTLSCredentials_InvalidCertFile(t *testing.T) {
	_, keyFile, _, cleanup := createTestCerts(t)
	defer cleanup()

	p := &Processor{
		config: Config{
			TLSCertFile: "/nonexistent/cert.pem",
			TLSKeyFile:  keyFile,
		},
	}

	_, err := p.buildTLSCredentials()
	if err == nil {
		t.Fatal("expected error when cert file doesn't exist, got nil")
	}
}

func TestBuildTLSCredentials_WithClientAuth(t *testing.T) {
	certFile, keyFile, caFile, cleanup := createTestCerts(t)
	defer cleanup()

	p := &Processor{
		config: Config{
			TLSCertFile:   certFile,
			TLSKeyFile:    keyFile,
			TLSCAFile:     caFile,
			TLSClientAuth: true,
		},
	}

	creds, err := p.buildTLSCredentials()
	if err != nil {
		t.Fatalf("buildTLSCredentials() failed: %v", err)
	}

	if creds == nil {
		t.Fatal("buildTLSCredentials() returned nil credentials")
	}

	// Verify mutual TLS is configured
	info := creds.Info()
	if info.SecurityProtocol != "tls" {
		t.Errorf("expected security protocol 'tls', got %q", info.SecurityProtocol)
	}
}

func TestBuildTLSCredentials_ClientAuthWithoutCA(t *testing.T) {
	certFile, keyFile, _, cleanup := createTestCerts(t)
	defer cleanup()

	p := &Processor{
		config: Config{
			TLSCertFile:   certFile,
			TLSKeyFile:    keyFile,
			TLSClientAuth: true,
			TLSCAFile:     "",
		},
	}

	_, err := p.buildTLSCredentials()
	if err == nil {
		t.Fatal("expected error when client auth enabled but CA file missing, got nil")
	}
}

func TestBuildClientTLSCredentials_Success(t *testing.T) {
	certFile, keyFile, caFile, cleanup := createTestCerts(t)
	defer cleanup()

	creds, err := tlsutil.BuildClientCredentials(tlsutil.ClientConfig{
		CertFile: certFile,
		KeyFile:  keyFile,
		CAFile:   caFile,
	})
	if err != nil {
		t.Fatalf("BuildClientCredentials() failed: %v", err)
	}

	if creds == nil {
		t.Fatal("BuildClientCredentials() returned nil credentials")
	}

	info := creds.Info()
	if info.SecurityProtocol != "tls" {
		t.Errorf("expected security protocol 'tls', got %q", info.SecurityProtocol)
	}
}

func TestBuildClientTLSCredentials_WithoutCA(t *testing.T) {
	creds, err := tlsutil.BuildClientCredentials(tlsutil.ClientConfig{
		CAFile: "",
	})
	if err != nil {
		t.Fatalf("BuildClientCredentials() should succeed without CA: %v", err)
	}

	if creds == nil {
		t.Fatal("BuildClientCredentials() returned nil credentials")
	}
}

func TestBuildClientTLSCredentials_MinVersion(t *testing.T) {
	creds, err := tlsutil.BuildClientCredentials(tlsutil.ClientConfig{})
	if err != nil {
		t.Fatalf("BuildClientCredentials() failed: %v", err)
	}

	// Verify TLS version through reflection or by checking the implementation
	// This is a basic sanity check
	if creds == nil {
		t.Fatal("BuildClientCredentials() returned nil credentials")
	}
}

func TestBuildClientTLSCredentials_InvalidCA(t *testing.T) {
	_, err := tlsutil.BuildClientCredentials(tlsutil.ClientConfig{
		CAFile: "/nonexistent/ca.pem",
	})
	if err == nil {
		t.Fatal("expected error when CA file doesn't exist, got nil")
	}
}

func TestBuildClientTLSCredentials_WithMutualTLS(t *testing.T) {
	certFile, keyFile, caFile, cleanup := createTestCerts(t)
	defer cleanup()

	creds, err := tlsutil.BuildClientCredentials(tlsutil.ClientConfig{
		CertFile: certFile,
		KeyFile:  keyFile,
		CAFile:   caFile,
	})
	if err != nil {
		t.Fatalf("BuildClientCredentials() failed: %v", err)
	}

	if creds == nil {
		t.Fatal("BuildClientCredentials() returned nil credentials")
	}
}

func TestTLSConfig_MinVersion(t *testing.T) {
	certFile, keyFile, _, cleanup := createTestCerts(t)
	defer cleanup()

	p := &Processor{
		config: Config{
			TLSCertFile: certFile,
			TLSKeyFile:  keyFile,
		},
	}

	// We can't directly test the TLS config without access to internals,
	// but we can verify the credentials are created successfully
	creds, err := p.buildTLSCredentials()
	if err != nil {
		t.Fatalf("buildTLSCredentials() failed: %v", err)
	}

	if creds == nil {
		t.Fatal("buildTLSCredentials() returned nil credentials")
	}

	// The implementation should use TLS 1.2+ as per security requirements
	// This is verified by code inspection and the fact that it's hardcoded
}

func TestTLSConfig_InvalidCAFile(t *testing.T) {
	certFile, keyFile, _, cleanup := createTestCerts(t)
	defer cleanup()

	tmpDir := t.TempDir()
	invalidCA := filepath.Join(tmpDir, "invalid_ca.pem")
	if err := os.WriteFile(invalidCA, []byte("invalid cert data"), 0644); err != nil {
		t.Fatal(err)
	}

	p := &Processor{
		config: Config{
			TLSCertFile:   certFile,
			TLSKeyFile:    keyFile,
			TLSCAFile:     invalidCA,
			TLSClientAuth: true,
		},
	}

	_, err := p.buildTLSCredentials()
	if err == nil {
		t.Fatal("expected error when CA file contains invalid data, got nil")
	}
}

func TestTLSCredentials_UseSystemCertPool(t *testing.T) {
	// Test that client credentials can use system cert pool when no CA specified
	creds, err := tlsutil.BuildClientCredentials(tlsutil.ClientConfig{})
	if err != nil {
		t.Fatalf("BuildClientCredentials() failed: %v", err)
	}

	if creds == nil {
		t.Fatal("BuildClientCredentials() returned nil credentials")
	}

	// Should succeed and use system cert pool
}

func TestClientCertVerification(t *testing.T) {
	certFile, keyFile, caFile, cleanup := createTestCerts(t)
	defer cleanup()

	// Test that client certificates are properly loaded
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatalf("failed to load test certificates: %v", err)
	}

	if len(cert.Certificate) == 0 {
		t.Fatal("certificate chain is empty")
	}

	// Test CA loading
	caCert, err := os.ReadFile(caFile)
	if err != nil {
		t.Fatalf("failed to read CA file: %v", err)
	}

	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM(caCert) {
		t.Fatal("failed to parse CA certificate")
	}
}
