package hunter

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

	h := &Hunter{
		config: Config{
			TLSCAFile:   caFile,
			TLSCertFile: certFile,
			TLSKeyFile:  keyFile,
		},
	}

	creds, err := h.buildTLSCredentials()
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
	h := &Hunter{
		config: Config{
			TLSSkipVerify: false,
		},
	}

	creds, err := h.buildTLSCredentials()
	if err != nil {
		t.Fatalf("buildTLSCredentials() failed: %v", err)
	}

	if creds == nil {
		t.Fatal("buildTLSCredentials() returned nil credentials")
	}

	// Should succeed with system cert pool
}

func TestBuildTLSCredentials_SkipVerify(t *testing.T) {
	h := &Hunter{
		config: Config{
			TLSSkipVerify: true,
		},
	}

	creds, err := h.buildTLSCredentials()
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

	h := &Hunter{
		config: Config{
			TLSCAFile: caFile,
		},
	}

	creds, err := h.buildTLSCredentials()
	if err != nil {
		t.Fatalf("buildTLSCredentials() failed: %v", err)
	}

	if creds == nil {
		t.Fatal("buildTLSCredentials() returned nil credentials")
	}
}

func TestBuildTLSCredentials_InvalidCAFile(t *testing.T) {
	h := &Hunter{
		config: Config{
			TLSCAFile: "/nonexistent/ca.pem",
		},
	}

	_, err := h.buildTLSCredentials()
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

	h := &Hunter{
		config: Config{
			TLSCAFile: invalidCA,
		},
	}

	_, err := h.buildTLSCredentials()
	if err == nil {
		t.Fatal("expected error when CA file contains invalid data, got nil")
	}
}

func TestBuildTLSCredentials_WithClientCert(t *testing.T) {
	certFile, keyFile, caFile, cleanup := createTestCerts(t)
	defer cleanup()

	h := &Hunter{
		config: Config{
			TLSCAFile:   caFile,
			TLSCertFile: certFile,
			TLSKeyFile:  keyFile,
		},
	}

	creds, err := h.buildTLSCredentials()
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

	h := &Hunter{
		config: Config{
			TLSCAFile:   caFile,
			TLSCertFile: "/nonexistent/cert.pem",
			TLSKeyFile:  keyFile,
		},
	}

	_, err := h.buildTLSCredentials()
	if err == nil {
		t.Fatal("expected error when cert file doesn't exist, got nil")
	}
}

func TestBuildTLSCredentials_CertWithoutKey(t *testing.T) {
	certFile, _, caFile, cleanup := createTestCerts(t)
	defer cleanup()

	h := &Hunter{
		config: Config{
			TLSCAFile:   caFile,
			TLSCertFile: certFile,
			TLSKeyFile:  "",
		},
	}

	// Should succeed - partial cert/key is ignored
	creds, err := h.buildTLSCredentials()
	if err != nil {
		t.Fatalf("buildTLSCredentials() failed: %v", err)
	}

	if creds == nil {
		t.Fatal("buildTLSCredentials() returned nil credentials")
	}
}

func TestBuildTLSCredentials_KeyWithoutCert(t *testing.T) {
	_, keyFile, caFile, cleanup := createTestCerts(t)
	defer cleanup()

	h := &Hunter{
		config: Config{
			TLSCAFile:   caFile,
			TLSCertFile: "",
			TLSKeyFile:  keyFile,
		},
	}

	// Should succeed - partial cert/key is ignored
	creds, err := h.buildTLSCredentials()
	if err != nil {
		t.Fatalf("buildTLSCredentials() failed: %v", err)
	}

	if creds == nil {
		t.Fatal("buildTLSCredentials() returned nil credentials")
	}
}

func TestBuildTLSCredentials_ServerNameOverride(t *testing.T) {
	h := &Hunter{
		config: Config{
			TLSServerNameOverride: "custom.example.com",
		},
	}

	creds, err := h.buildTLSCredentials()
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
	h := &Hunter{
		config: Config{
			TLSCAFile:             caFile,
			TLSCertFile:           certFile,
			TLSKeyFile:            keyFile,
			TLSSkipVerify:         false,
			TLSServerNameOverride: "localhost",
		},
	}

	creds, err := h.buildTLSCredentials()
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
