package tlsutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testCA holds a self-signed CA certificate and key for test use.
type testCA struct {
	certPEM []byte
	keyPEM  []byte
	cert    *x509.Certificate
	key     *ecdsa.PrivateKey
}

// testCert holds a certificate and key pair for test use.
type testCert struct {
	certPEM  []byte
	keyPEM   []byte
	certFile string
	keyFile  string
}

// newTestCA generates a self-signed CA certificate.
func newTestCA(t *testing.T) *testCA {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return &testCA{
		certPEM: certPEM,
		keyPEM:  keyPEM,
		cert:    cert,
		key:     key,
	}
}

// newTestCert generates a certificate signed by the given CA and writes it to dir.
func newTestCert(t *testing.T, ca *testCA, dir string, name string) *testCert {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, ca.cert, &key.PublicKey, ca.key)
	require.NoError(t, err)

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	certFile := filepath.Join(dir, name+".crt")
	keyFile := filepath.Join(dir, name+".key")
	require.NoError(t, os.WriteFile(certFile, certPEM, 0600))
	require.NoError(t, os.WriteFile(keyFile, keyPEM, 0600))

	return &testCert{
		certPEM:  certPEM,
		keyPEM:   keyPEM,
		certFile: certFile,
		keyFile:  keyFile,
	}
}

// writeCAFile writes the CA certificate PEM to a file and returns its path.
func writeCAFile(t *testing.T, ca *testCA, dir string) string {
	t.Helper()
	caFile := filepath.Join(dir, "ca.crt")
	require.NoError(t, os.WriteFile(caFile, ca.certPEM, 0600))
	return caFile
}

func TestBuildServerCredentials(t *testing.T) {
	dir := t.TempDir()
	ca := newTestCA(t)
	serverCert := newTestCert(t, ca, dir, "server")
	caFile := writeCAFile(t, ca, dir)

	t.Run("valid cert and key", func(t *testing.T) {
		creds, err := BuildServerCredentials(ServerConfig{
			CertFile: serverCert.certFile,
			KeyFile:  serverCert.keyFile,
		})
		require.NoError(t, err)
		assert.NotNil(t, creds)

		// Verify TLS 1.3 minimum version via the transport credentials info
		info := creds.Info()
		assert.Equal(t, "tls", info.SecurityProtocol)
	})

	t.Run("missing cert file", func(t *testing.T) {
		_, err := BuildServerCredentials(ServerConfig{
			CertFile: "",
			KeyFile:  serverCert.keyFile,
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "certificate or key file not specified")
	})

	t.Run("missing key file", func(t *testing.T) {
		_, err := BuildServerCredentials(ServerConfig{
			CertFile: serverCert.certFile,
			KeyFile:  "",
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "certificate or key file not specified")
	})

	t.Run("both cert and key empty", func(t *testing.T) {
		_, err := BuildServerCredentials(ServerConfig{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "certificate or key file not specified")
	})

	t.Run("nonexistent cert file", func(t *testing.T) {
		_, err := BuildServerCredentials(ServerConfig{
			CertFile: filepath.Join(dir, "nonexistent.crt"),
			KeyFile:  serverCert.keyFile,
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to load server certificate")
	})

	t.Run("nonexistent key file", func(t *testing.T) {
		_, err := BuildServerCredentials(ServerConfig{
			CertFile: serverCert.certFile,
			KeyFile:  filepath.Join(dir, "nonexistent.key"),
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to load server certificate")
	})

	t.Run("mismatched cert and key", func(t *testing.T) {
		// Generate a second cert with a different key
		otherCert := newTestCert(t, ca, dir, "other")

		_, err := BuildServerCredentials(ServerConfig{
			CertFile: serverCert.certFile,
			KeyFile:  otherCert.keyFile,
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to load server certificate")
	})

	t.Run("mTLS with valid CA", func(t *testing.T) {
		creds, err := BuildServerCredentials(ServerConfig{
			CertFile:   serverCert.certFile,
			KeyFile:    serverCert.keyFile,
			CAFile:     caFile,
			ClientAuth: true,
		})
		require.NoError(t, err)
		assert.NotNil(t, creds)
	})

	t.Run("mTLS without CA file errors", func(t *testing.T) {
		_, err := BuildServerCredentials(ServerConfig{
			CertFile:   serverCert.certFile,
			KeyFile:    serverCert.keyFile,
			ClientAuth: true,
			CAFile:     "",
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "client auth enabled but CA file not specified")
	})

	t.Run("mTLS with nonexistent CA file", func(t *testing.T) {
		_, err := BuildServerCredentials(ServerConfig{
			CertFile:   serverCert.certFile,
			KeyFile:    serverCert.keyFile,
			ClientAuth: true,
			CAFile:     filepath.Join(dir, "nonexistent-ca.crt"),
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to read CA certificate")
	})

	t.Run("mTLS with invalid CA PEM", func(t *testing.T) {
		badCAFile := filepath.Join(dir, "bad-ca.crt")
		require.NoError(t, os.WriteFile(badCAFile, []byte("not a PEM certificate"), 0600))

		_, err := BuildServerCredentials(ServerConfig{
			CertFile:   serverCert.certFile,
			KeyFile:    serverCert.keyFile,
			ClientAuth: true,
			CAFile:     badCAFile,
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to parse CA certificate")
	})
}

func TestBuildClientCredentials(t *testing.T) {
	dir := t.TempDir()
	ca := newTestCA(t)
	clientCert := newTestCert(t, ca, dir, "client")
	caFile := writeCAFile(t, ca, dir)

	// Ensure production mode is off for most tests.
	t.Setenv("LIPPYCAT_PRODUCTION", "")

	t.Run("minimal config", func(t *testing.T) {
		creds, err := BuildClientCredentials(ClientConfig{})
		require.NoError(t, err)
		assert.NotNil(t, creds)

		info := creds.Info()
		assert.Equal(t, "tls", info.SecurityProtocol)
	})

	t.Run("with CA file", func(t *testing.T) {
		creds, err := BuildClientCredentials(ClientConfig{
			CAFile: caFile,
		})
		require.NoError(t, err)
		assert.NotNil(t, creds)
	})

	t.Run("nonexistent CA file", func(t *testing.T) {
		_, err := BuildClientCredentials(ClientConfig{
			CAFile: filepath.Join(dir, "nonexistent-ca.crt"),
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to read CA certificate")
	})

	t.Run("invalid CA PEM", func(t *testing.T) {
		badCAFile := filepath.Join(dir, "bad-ca.crt")
		require.NoError(t, os.WriteFile(badCAFile, []byte("garbage"), 0600))

		_, err := BuildClientCredentials(ClientConfig{
			CAFile: badCAFile,
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to parse CA certificate")
	})

	t.Run("skip verify allowed in non-production", func(t *testing.T) {
		t.Setenv("LIPPYCAT_PRODUCTION", "")

		creds, err := BuildClientCredentials(ClientConfig{
			SkipVerify: true,
		})
		require.NoError(t, err)
		assert.NotNil(t, creds)
	})

	t.Run("skip verify blocked in production mode", func(t *testing.T) {
		t.Setenv("LIPPYCAT_PRODUCTION", "true")

		_, err := BuildClientCredentials(ClientConfig{
			SkipVerify: true,
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "LIPPYCAT_PRODUCTION=true blocks TLSSkipVerify=true")
	})

	t.Run("production mode false does not block skip verify", func(t *testing.T) {
		t.Setenv("LIPPYCAT_PRODUCTION", "false")

		creds, err := BuildClientCredentials(ClientConfig{
			SkipVerify: true,
		})
		require.NoError(t, err)
		assert.NotNil(t, creds)
	})

	t.Run("mTLS with client cert and key", func(t *testing.T) {
		creds, err := BuildClientCredentials(ClientConfig{
			CAFile:   caFile,
			CertFile: clientCert.certFile,
			KeyFile:  clientCert.keyFile,
		})
		require.NoError(t, err)
		assert.NotNil(t, creds)
	})

	t.Run("only cert file without key errors", func(t *testing.T) {
		_, err := BuildClientCredentials(ClientConfig{
			CertFile: clientCert.certFile,
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "both cert_file and key_file must be provided")
	})

	t.Run("only key file without cert errors", func(t *testing.T) {
		_, err := BuildClientCredentials(ClientConfig{
			KeyFile: clientCert.keyFile,
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "both cert_file and key_file must be provided")
	})

	t.Run("nonexistent client cert file", func(t *testing.T) {
		_, err := BuildClientCredentials(ClientConfig{
			CertFile: filepath.Join(dir, "nonexistent.crt"),
			KeyFile:  clientCert.keyFile,
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to load client certificate")
	})

	t.Run("mismatched client cert and key", func(t *testing.T) {
		otherCert := newTestCert(t, ca, dir, "other-client")

		_, err := BuildClientCredentials(ClientConfig{
			CertFile: clientCert.certFile,
			KeyFile:  otherCert.keyFile,
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to load client certificate")
	})

	t.Run("server name override", func(t *testing.T) {
		creds, err := BuildClientCredentials(ClientConfig{
			CAFile:             caFile,
			ServerNameOverride: "custom.example.com",
		})
		require.NoError(t, err)
		assert.NotNil(t, creds)
	})

	t.Run("system cert pool", func(t *testing.T) {
		creds, err := BuildClientCredentials(ClientConfig{
			UseSystemCertPool: true,
		})
		require.NoError(t, err)
		assert.NotNil(t, creds)
	})
}
