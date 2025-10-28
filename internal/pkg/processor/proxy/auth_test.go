package proxy

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log/slog"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// generateTestCertificate generates a self-signed RSA certificate for testing
func generateTestCertificate(t *testing.T) (certPEM, keyPEM []byte) {
	t.Helper()

	// Generate RSA private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err, "failed to generate RSA key")

	// Create certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "test-processor",
			Organization: []string{"lippycat-test"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	// Create self-signed certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	require.NoError(t, err, "failed to create certificate")

	// Encode certificate to PEM
	certPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	// Encode private key to PEM (PKCS8 format)
	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	require.NoError(t, err, "failed to marshal private key")

	keyPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateKeyBytes,
	})

	return certPEM, keyPEM
}

func TestManager_IssueAuthToken(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	certPEM, keyPEM := generateTestCertificate(t)

	t.Run("successful token issuance", func(t *testing.T) {
		mgr := NewManager(logger, "proc-1")
		mgr.SetTLSCredentials(certPEM, keyPEM)

		token, err := mgr.IssueAuthToken("proc-2")
		require.NoError(t, err)
		require.NotNil(t, token)

		assert.Equal(t, "proc-2", token.ProcessorID)
		assert.NotEmpty(t, token.Signature)
		assert.False(t, token.IssuedAt.IsZero())
		assert.False(t, token.ExpiresAt.IsZero())
		assert.WithinDuration(t, time.Now(), token.IssuedAt, 1*time.Second)
		assert.WithinDuration(t, time.Now().Add(TokenTTL), token.ExpiresAt, 1*time.Second)
	})

	t.Run("token without TLS credentials", func(t *testing.T) {
		mgr := NewManager(logger, "proc-1")
		// Don't set TLS credentials

		token, err := mgr.IssueAuthToken("proc-2")
		assert.ErrorIs(t, err, ErrNoTLSCredentials)
		assert.Nil(t, token)
	})

	t.Run("token has 5-minute TTL", func(t *testing.T) {
		mgr := NewManager(logger, "proc-1")
		mgr.SetTLSCredentials(certPEM, keyPEM)

		token, err := mgr.IssueAuthToken("proc-2")
		require.NoError(t, err)

		expectedExpiration := token.IssuedAt.Add(5 * time.Minute)
		assert.Equal(t, expectedExpiration, token.ExpiresAt)
	})

	t.Run("different processors get different tokens", func(t *testing.T) {
		mgr := NewManager(logger, "proc-1")
		mgr.SetTLSCredentials(certPEM, keyPEM)

		token1, err := mgr.IssueAuthToken("proc-2")
		require.NoError(t, err)

		token2, err := mgr.IssueAuthToken("proc-3")
		require.NoError(t, err)

		assert.NotEqual(t, token1.ProcessorID, token2.ProcessorID)
		assert.NotEqual(t, token1.Signature, token2.Signature)
	})
}

func TestManager_VerifyAuthToken(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	certPEM, keyPEM := generateTestCertificate(t)

	t.Run("valid token passes verification", func(t *testing.T) {
		mgr := NewManager(logger, "proc-1")
		mgr.SetTLSCredentials(certPEM, keyPEM)

		token, err := mgr.IssueAuthToken("proc-2")
		require.NoError(t, err)

		err = mgr.VerifyAuthToken(token, "proc-2")
		assert.NoError(t, err)
	})

	t.Run("expired token fails verification", func(t *testing.T) {
		mgr := NewManager(logger, "proc-1")
		mgr.SetTLSCredentials(certPEM, keyPEM)

		token, err := mgr.IssueAuthToken("proc-2")
		require.NoError(t, err)

		// Manually expire the token
		token.ExpiresAt = time.Now().Add(-1 * time.Minute)

		err = mgr.VerifyAuthToken(token, "proc-2")
		assert.ErrorIs(t, err, ErrTokenExpired)
	})

	t.Run("invalid signature fails verification", func(t *testing.T) {
		mgr := NewManager(logger, "proc-1")
		mgr.SetTLSCredentials(certPEM, keyPEM)

		token, err := mgr.IssueAuthToken("proc-2")
		require.NoError(t, err)

		// Corrupt the signature
		token.Signature = []byte("invalid-signature")

		err = mgr.VerifyAuthToken(token, "proc-2")
		assert.ErrorIs(t, err, ErrInvalidSignature)
	})

	t.Run("modified token fails verification", func(t *testing.T) {
		mgr := NewManager(logger, "proc-1")
		mgr.SetTLSCredentials(certPEM, keyPEM)

		token, err := mgr.IssueAuthToken("proc-2")
		require.NoError(t, err)

		// Modify the processor ID after signing
		token.ProcessorID = "proc-3"

		err = mgr.VerifyAuthToken(token, "proc-3")
		// Signature will be invalid because we changed the data
		assert.ErrorIs(t, err, ErrInvalidSignature)
	})

	t.Run("mismatched processor ID fails verification", func(t *testing.T) {
		mgr := NewManager(logger, "proc-1")
		mgr.SetTLSCredentials(certPEM, keyPEM)

		token, err := mgr.IssueAuthToken("proc-2")
		require.NoError(t, err)

		err = mgr.VerifyAuthToken(token, "proc-3")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "processor ID mismatch")
	})

	t.Run("nil token fails verification", func(t *testing.T) {
		mgr := NewManager(logger, "proc-1")
		mgr.SetTLSCredentials(certPEM, keyPEM)

		err := mgr.VerifyAuthToken(nil, "proc-2")
		assert.ErrorIs(t, err, ErrInvalidToken)
	})

	t.Run("verification without TLS credentials fails", func(t *testing.T) {
		mgr := NewManager(logger, "proc-1")
		mgr.SetTLSCredentials(certPEM, keyPEM)

		token, err := mgr.IssueAuthToken("proc-2")
		require.NoError(t, err)

		// Create new manager without TLS credentials
		mgr2 := NewManager(logger, "proc-2")

		err = mgr2.VerifyAuthToken(token, "proc-2")
		assert.ErrorIs(t, err, ErrNoTLSCredentials)
	})
}

func TestManager_TokenExpiration(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	certPEM, keyPEM := generateTestCertificate(t)

	t.Run("token just before expiration is valid", func(t *testing.T) {
		mgr := NewManager(logger, "proc-1")
		mgr.SetTLSCredentials(certPEM, keyPEM)

		token, err := mgr.IssueAuthToken("proc-2")
		require.NoError(t, err)

		// Set expiration to 1 second from now
		token.IssuedAt = time.Now().Add(-TokenTTL + 1*time.Second)
		token.ExpiresAt = time.Now().Add(1 * time.Second)

		// Re-sign with new timestamps
		signature, err := mgr.signToken(token)
		require.NoError(t, err)
		token.Signature = signature

		err = mgr.VerifyAuthToken(token, "proc-2")
		assert.NoError(t, err)
	})

	t.Run("token just after expiration is invalid", func(t *testing.T) {
		mgr := NewManager(logger, "proc-1")
		mgr.SetTLSCredentials(certPEM, keyPEM)

		token, err := mgr.IssueAuthToken("proc-2")
		require.NoError(t, err)

		// Set expiration to 1 second ago
		token.ExpiresAt = time.Now().Add(-1 * time.Second)

		err = mgr.VerifyAuthToken(token, "proc-2")
		assert.ErrorIs(t, err, ErrTokenExpired)
	})
}

func TestManager_SignAndVerifyToken(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	certPEM, keyPEM := generateTestCertificate(t)

	t.Run("sign and verify token", func(t *testing.T) {
		mgr := NewManager(logger, "proc-1")
		mgr.SetTLSCredentials(certPEM, keyPEM)

		token := &AuthorizationToken{
			ProcessorID: "proc-2",
			IssuedAt:    time.Now(),
			ExpiresAt:   time.Now().Add(TokenTTL),
		}

		signature, err := mgr.signToken(token)
		require.NoError(t, err)
		assert.NotEmpty(t, signature)

		token.Signature = signature

		err = mgr.verifyTokenSignature(token)
		assert.NoError(t, err)
	})

	t.Run("verify fails with wrong certificate", func(t *testing.T) {
		mgr := NewManager(logger, "proc-1")
		mgr.SetTLSCredentials(certPEM, keyPEM)

		token, err := mgr.IssueAuthToken("proc-2")
		require.NoError(t, err)

		// Create different certificate
		certPEM2, keyPEM2 := generateTestCertificate(t)
		mgr2 := NewManager(logger, "proc-2")
		mgr2.SetTLSCredentials(certPEM2, keyPEM2)

		// Try to verify token signed by mgr using mgr2's certificate
		err = mgr2.verifyTokenSignature(token)
		assert.ErrorIs(t, err, ErrInvalidSignature)
	})
}

func TestManager_HashToken(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	mgr := NewManager(logger, "proc-1")

	t.Run("same token produces same hash", func(t *testing.T) {
		token := &AuthorizationToken{
			ProcessorID: "proc-2",
			IssuedAt:    time.Unix(1234567890, 0),
			ExpiresAt:   time.Unix(1234567890+300, 0),
		}

		hash1 := mgr.hashToken(token)
		hash2 := mgr.hashToken(token)

		assert.Equal(t, hash1, hash2)
	})

	t.Run("different tokens produce different hashes", func(t *testing.T) {
		token1 := &AuthorizationToken{
			ProcessorID: "proc-2",
			IssuedAt:    time.Unix(1234567890, 0),
			ExpiresAt:   time.Unix(1234567890+300, 0),
		}

		token2 := &AuthorizationToken{
			ProcessorID: "proc-3",
			IssuedAt:    time.Unix(1234567890, 0),
			ExpiresAt:   time.Unix(1234567890+300, 0),
		}

		hash1 := mgr.hashToken(token1)
		hash2 := mgr.hashToken(token2)

		assert.NotEqual(t, hash1, hash2)
	})

	t.Run("signature not included in hash", func(t *testing.T) {
		token1 := &AuthorizationToken{
			ProcessorID: "proc-2",
			IssuedAt:    time.Unix(1234567890, 0),
			ExpiresAt:   time.Unix(1234567890+300, 0),
			Signature:   []byte("signature-1"),
		}

		token2 := &AuthorizationToken{
			ProcessorID: "proc-2",
			IssuedAt:    time.Unix(1234567890, 0),
			ExpiresAt:   time.Unix(1234567890+300, 0),
			Signature:   []byte("signature-2"),
		}

		hash1 := mgr.hashToken(token1)
		hash2 := mgr.hashToken(token2)

		// Hashes should be equal because signature is not included
		assert.Equal(t, hash1, hash2)
	})
}

func TestValidateHierarchyDepth(t *testing.T) {
	tests := []struct {
		name      string
		depth     int32
		expectErr bool
	}{
		{"depth 0", 0, false},
		{"depth 1", 1, false},
		{"depth 5", 5, false},
		{"depth 10 (max)", 10, false},
		{"depth 11 (over max)", 11, true},
		{"depth 100", 100, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateHierarchyDepth(tt.depth)
			if tt.expectErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "exceeds maximum")
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestDetectCycle(t *testing.T) {
	tests := []struct {
		name          string
		processorID   string
		upstreamChain []string
		expectCycle   bool
	}{
		{
			name:          "no cycle - empty chain",
			processorID:   "proc-1",
			upstreamChain: []string{},
			expectCycle:   false,
		},
		{
			name:          "no cycle - different processors",
			processorID:   "proc-3",
			upstreamChain: []string{"proc-1", "proc-2"},
			expectCycle:   false,
		},
		{
			name:          "cycle detected - processor in chain",
			processorID:   "proc-2",
			upstreamChain: []string{"proc-1", "proc-2", "proc-3"},
			expectCycle:   true,
		},
		{
			name:          "cycle detected - self loop",
			processorID:   "proc-1",
			upstreamChain: []string{"proc-1"},
			expectCycle:   true,
		},
		{
			name:          "cycle detected - at end of chain",
			processorID:   "proc-1",
			upstreamChain: []string{"proc-2", "proc-3", "proc-1"},
			expectCycle:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hasCycle := DetectCycle(tt.processorID, tt.upstreamChain)
			assert.Equal(t, tt.expectCycle, hasCycle)
		})
	}
}

func TestManager_TokenIntegration(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	certPEM, keyPEM := generateTestCertificate(t)

	t.Run("end-to-end token lifecycle", func(t *testing.T) {
		// Root processor issues token
		rootMgr := NewManager(logger, "root")
		rootMgr.SetTLSCredentials(certPEM, keyPEM)

		token, err := rootMgr.IssueAuthToken("downstream-1")
		require.NoError(t, err)

		// Downstream processor verifies token
		downstreamMgr := NewManager(logger, "downstream-1")
		downstreamMgr.SetTLSCredentials(certPEM, keyPEM)

		err = downstreamMgr.VerifyAuthToken(token, "downstream-1")
		assert.NoError(t, err)
	})

	t.Run("multi-hop token chain", func(t *testing.T) {
		// Simulate 3-level hierarchy: root → middle → leaf
		rootMgr := NewManager(logger, "root")
		rootMgr.SetTLSCredentials(certPEM, keyPEM)

		// Root issues token for middle processor
		tokenForMiddle, err := rootMgr.IssueAuthToken("middle")
		require.NoError(t, err)

		// Middle processor verifies token
		middleMgr := NewManager(logger, "middle")
		middleMgr.SetTLSCredentials(certPEM, keyPEM)

		err = middleMgr.VerifyAuthToken(tokenForMiddle, "middle")
		assert.NoError(t, err)

		// Root issues token for leaf processor
		tokenForLeaf, err := rootMgr.IssueAuthToken("leaf")
		require.NoError(t, err)

		// Leaf processor verifies token
		leafMgr := NewManager(logger, "leaf")
		leafMgr.SetTLSCredentials(certPEM, keyPEM)

		err = leafMgr.VerifyAuthToken(tokenForLeaf, "leaf")
		assert.NoError(t, err)
	})
}
