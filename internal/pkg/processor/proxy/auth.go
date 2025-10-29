package proxy

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"github.com/endorses/lippycat/api/gen/management"
)

const (
	// TokenTTL is the time-to-live for authorization tokens
	TokenTTL = 5 * time.Minute

	// MaxHierarchyDepth is the maximum allowed hierarchy depth
	MaxHierarchyDepth = 10
)

var (
	// ErrTokenExpired is returned when a token has expired
	ErrTokenExpired = errors.New("authorization token expired")

	// ErrInvalidSignature is returned when token signature verification fails
	ErrInvalidSignature = errors.New("invalid token signature")

	// ErrNoTLSCredentials is returned when trying to sign tokens without TLS credentials
	ErrNoTLSCredentials = errors.New("TLS credentials not configured")

	// ErrInvalidToken is returned when token format is invalid
	ErrInvalidToken = errors.New("invalid token format")
)

// AuthorizationToken represents a signed authorization token for proxied operations
type AuthorizationToken struct {
	ProcessorID string    // Target processor ID
	IssuedAt    time.Time // Token issue timestamp
	ExpiresAt   time.Time // Token expiration timestamp
	Signature   []byte    // Cryptographic signature
}

// IssueAuthToken creates a new authorization token for the target processor.
// The token is signed with this processor's TLS private key and has a 5-minute TTL.
//
// Returns ErrNoTLSCredentials if TLS credentials have not been configured via
// SetTLSCredentials().
func (m *Manager) IssueAuthToken(targetProcessorID string) (*AuthorizationToken, error) {
	if m.tlsPrivateKey == nil {
		return nil, ErrNoTLSCredentials
	}

	now := time.Now()
	token := &AuthorizationToken{
		ProcessorID: targetProcessorID,
		IssuedAt:    now,
		ExpiresAt:   now.Add(TokenTTL),
	}

	// Sign the token
	signature, err := m.signToken(token)
	if err != nil {
		return nil, fmt.Errorf("failed to sign token: %w", err)
	}

	token.Signature = signature

	m.logger.Debug("issued authorization token",
		"target_processor", targetProcessorID,
		"expires_at", token.ExpiresAt)

	return token, nil
}

// VerifyAuthToken verifies an authorization token's signature and expiration.
// Returns nil if the token is valid, or an error describing the validation failure.
//
// Verification checks:
//   - Token has not expired
//   - Signature is valid (signed by root processor's private key)
//   - Target processor ID matches expected value
func (m *Manager) VerifyAuthToken(token *AuthorizationToken, expectedProcessorID string) error {
	if token == nil {
		return ErrInvalidToken
	}

	// Check expiration
	if time.Now().After(token.ExpiresAt) {
		m.logger.Warn("rejected expired authorization token",
			"target_processor", token.ProcessorID,
			"expired_at", token.ExpiresAt)
		return ErrTokenExpired
	}

	// Check processor ID matches
	if token.ProcessorID != expectedProcessorID {
		m.logger.Warn("rejected token with mismatched processor ID",
			"expected", expectedProcessorID,
			"got", token.ProcessorID)
		return fmt.Errorf("token processor ID mismatch: expected %s, got %s",
			expectedProcessorID, token.ProcessorID)
	}

	// Verify signature
	if err := m.verifyTokenSignature(token); err != nil {
		m.logger.Warn("rejected token with invalid signature",
			"target_processor", token.ProcessorID,
			"error", err)
		return err
	}

	m.logger.Debug("verified authorization token",
		"target_processor", token.ProcessorID)

	return nil
}

// signToken generates a cryptographic signature for the token using RSA-SHA256
func (m *Manager) signToken(token *AuthorizationToken) ([]byte, error) {
	// Parse private key from PEM
	block, _ := pem.Decode(m.tlsPrivateKey)
	if block == nil {
		return nil, errors.New("failed to decode PEM private key")
	}

	privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		// Try PKCS1 format
		privateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse private key: %w", err)
		}
	}

	rsaKey, ok := privateKey.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("private key is not RSA")
	}

	// Create hash of token data
	hash := m.hashToken(token)

	// Sign the hash
	signature, err := rsa.SignPKCS1v15(rand.Reader, rsaKey, crypto.SHA256, hash[:])
	if err != nil {
		return nil, fmt.Errorf("failed to sign: %w", err)
	}

	return signature, nil
}

// verifyTokenSignature verifies the token's signature using the processor's public key
func (m *Manager) verifyTokenSignature(token *AuthorizationToken) error {
	if m.tlsCert == nil {
		return ErrNoTLSCredentials
	}

	// Parse certificate from PEM
	block, _ := pem.Decode(m.tlsCert)
	if block == nil {
		return errors.New("failed to decode PEM certificate")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %w", err)
	}

	publicKey, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return errors.New("certificate public key is not RSA")
	}

	// Create hash of token data
	hash := m.hashToken(token)

	// Verify signature
	err = rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hash[:], token.Signature)
	if err != nil {
		return ErrInvalidSignature
	}

	return nil
}

// hashToken creates a SHA256 hash of the token's data (excluding signature)
func (m *Manager) hashToken(token *AuthorizationToken) [32]byte {
	data := fmt.Sprintf("%s|%d|%d",
		token.ProcessorID,
		token.IssuedAt.Unix(),
		token.ExpiresAt.Unix())

	return sha256.Sum256([]byte(data))
}

// ValidateHierarchyDepth checks if a processor can be added at the given depth
// Returns an error if the depth exceeds MaxHierarchyDepth
func ValidateHierarchyDepth(depth int32) error {
	if depth > MaxHierarchyDepth {
		return fmt.Errorf("hierarchy depth %d exceeds maximum %d",
			depth, MaxHierarchyDepth)
	}
	return nil
}

// DetectCycle checks if adding a processor would create a cycle in the hierarchy
// upstreamChain is the list of processor IDs from root to the parent processor
// Returns true if the processorID is already in the upstream chain
func DetectCycle(processorID string, upstreamChain []string) bool {
	for _, id := range upstreamChain {
		if id == processorID {
			return true
		}
	}
	return false
}

// ConvertProtoToken converts a protobuf AuthorizationToken to the internal type
// Returns ErrInvalidToken if the protobuf token is nil or invalid
func ConvertProtoToken(protoToken *management.AuthorizationToken) (*AuthorizationToken, error) {
	if protoToken == nil {
		return nil, ErrInvalidToken
	}

	// Convert Unix nanoseconds to time.Time
	issuedAt := time.Unix(0, protoToken.IssuedAtNs)
	expiresAt := time.Unix(0, protoToken.ExpiresAtNs)

	return &AuthorizationToken{
		ProcessorID: protoToken.TargetProcessorId,
		IssuedAt:    issuedAt,
		ExpiresAt:   expiresAt,
		Signature:   protoToken.Signature,
	}, nil
}

// ConvertToProtoToken converts an internal AuthorizationToken to protobuf format
// The issuerID and processorChain parameters are used for auditing
func ConvertToProtoToken(token *AuthorizationToken, issuerID string, processorChain []string) *management.AuthorizationToken {
	if token == nil {
		return nil
	}

	return &management.AuthorizationToken{
		Signature:         token.Signature,
		IssuedAtNs:        token.IssuedAt.UnixNano(),
		ExpiresAtNs:       token.ExpiresAt.UnixNano(),
		TargetProcessorId: token.ProcessorID,
		IssuerId:          issuerID,
		ProcessorChain:    processorChain,
	}
}
