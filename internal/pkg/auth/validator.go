package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"sync"

	"github.com/endorses/lippycat/internal/pkg/logger"
	"google.golang.org/grpc/metadata"
)

const (
	// APIKeyMetadataKey is the gRPC metadata key for API keys.
	APIKeyMetadataKey = "x-api-key"
)

// Validator validates API keys and checks permissions.
type Validator struct {
	config Config
	// keyMap maps API keys to their configuration for O(1) lookup.
	keyMap map[string]*APIKey
	mu     sync.RWMutex
}

// NewValidator creates a new API key validator.
func NewValidator(config Config) *Validator {
	v := &Validator{
		config: config,
		keyMap: make(map[string]*APIKey),
	}
	v.rebuildKeyMap()
	return v
}

// rebuildKeyMap rebuilds the internal key map from the config.
// Must be called with write lock held or during initialization.
func (v *Validator) rebuildKeyMap() {
	v.keyMap = make(map[string]*APIKey, len(v.config.APIKeys))
	for i := range v.config.APIKeys {
		key := &v.config.APIKeys[i]
		v.keyMap[key.Key] = key
	}
}

// UpdateConfig updates the validator configuration.
// This allows runtime configuration updates without restarting.
func (v *Validator) UpdateConfig(config Config) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.config = config
	v.rebuildKeyMap()
}

// IsEnabled returns whether authentication is enabled.
func (v *Validator) IsEnabled() bool {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.config.Enabled
}

// ValidateContext validates the API key in the context and checks for required role.
// Returns the API key configuration if valid, or an error if invalid/missing.
func (v *Validator) ValidateContext(ctx context.Context, requiredRole Role) (*APIKey, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()

	// If authentication is disabled, allow all requests
	if !v.config.Enabled {
		return nil, nil
	}

	// Extract API key from metadata
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		logger.Warn("Authentication failed: no metadata in context")
		return nil, ErrMissingAPIKey
	}

	values := md.Get(APIKeyMetadataKey)
	if len(values) == 0 {
		logger.Warn("Authentication failed: no API key in metadata")
		return nil, ErrMissingAPIKey
	}

	apiKeyStr := values[0]
	if apiKeyStr == "" {
		logger.Warn("Authentication failed: empty API key")
		return nil, ErrMissingAPIKey
	}

	// Look up the API key
	apiKey, ok := v.keyMap[apiKeyStr]
	if !ok {
		logger.Warn("Authentication failed: invalid API key", "key_prefix", maskAPIKey(apiKeyStr))
		return nil, ErrInvalidAPIKey
	}

	// Check if the key has the required role
	if !hasRole(apiKey.Role, requiredRole) {
		logger.Warn("Authentication failed: insufficient permissions",
			"description", apiKey.Description,
			"has_role", apiKey.Role,
			"required_role", requiredRole)
		return nil, ErrInsufficientPermissions
	}

	// Success
	logger.Debug("Authentication successful",
		"description", apiKey.Description,
		"role", apiKey.Role)

	return apiKey, nil
}

// hasRole checks if the provided role satisfies the required role.
// Admin role satisfies all requirements.
func hasRole(provided Role, required Role) bool {
	if provided == RoleAdmin {
		return true
	}
	return provided == required
}

// maskAPIKey returns a masked version of the API key for logging.
// Shows first 8 characters only to aid in debugging without exposing the full key.
func maskAPIKey(key string) string {
	if len(key) <= 8 {
		return "****"
	}
	return key[:8] + "****"
}

// LogAuthFailure logs an authentication failure with context for auditing.
func LogAuthFailure(ctx context.Context, err error, operation string) {
	// Extract any available metadata for audit log
	clientInfo := "unknown"
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		if userAgent := md.Get("user-agent"); len(userAgent) > 0 {
			clientInfo = userAgent[0]
		}
	}

	logger.Error("Authentication failure",
		"operation", operation,
		"error", err,
		"client_info", clientInfo)
}

// GenerateAPIKey generates a cryptographically random API key.
// Returns a 32-byte (256-bit) key encoded as URL-safe base64.
func GenerateAPIKey() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate random bytes: %w", err)
	}
	return base64.URLEncoding.EncodeToString(b), nil
}
