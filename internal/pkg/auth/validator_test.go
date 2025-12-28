package auth

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/metadata"
)

func TestValidator_ValidateContext(t *testing.T) {
	config := Config{
		Enabled: true,
		APIKeys: []APIKey{
			{
				Key:         "hunter-key-123",
				Role:        RoleHunter,
				Description: "Test hunter key",
			},
			{
				Key:         "subscriber-key-456",
				Role:        RoleSubscriber,
				Description: "Test subscriber key",
			},
			{
				Key:         "admin-key-789",
				Role:        RoleAdmin,
				Description: "Test admin key",
			},
		},
	}

	validator := NewValidator(config)

	tests := []struct {
		name         string
		apiKey       string
		requiredRole Role
		wantErr      error
		wantKey      *APIKey
	}{
		{
			name:         "valid hunter key for hunter role",
			apiKey:       "hunter-key-123",
			requiredRole: RoleHunter,
			wantErr:      nil,
			wantKey:      &config.APIKeys[0],
		},
		{
			name:         "valid subscriber key for subscriber role",
			apiKey:       "subscriber-key-456",
			requiredRole: RoleSubscriber,
			wantErr:      nil,
			wantKey:      &config.APIKeys[1],
		},
		{
			name:         "valid admin key for hunter role",
			apiKey:       "admin-key-789",
			requiredRole: RoleHunter,
			wantErr:      nil,
			wantKey:      &config.APIKeys[2],
		},
		{
			name:         "valid admin key for subscriber role",
			apiKey:       "admin-key-789",
			requiredRole: RoleSubscriber,
			wantErr:      nil,
			wantKey:      &config.APIKeys[2],
		},
		{
			name:         "invalid key",
			apiKey:       "invalid-key",
			requiredRole: RoleHunter,
			wantErr:      ErrInvalidAPIKey,
			wantKey:      nil,
		},
		{
			name:         "hunter key for subscriber role",
			apiKey:       "hunter-key-123",
			requiredRole: RoleSubscriber,
			wantErr:      ErrInsufficientPermissions,
			wantKey:      nil,
		},
		{
			name:         "subscriber key for hunter role",
			apiKey:       "subscriber-key-456",
			requiredRole: RoleHunter,
			wantErr:      ErrInsufficientPermissions,
			wantKey:      nil,
		},
		{
			name:         "missing API key",
			apiKey:       "",
			requiredRole: RoleHunter,
			wantErr:      ErrMissingAPIKey,
			wantKey:      nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create context with API key metadata
			ctx := context.Background()
			if tt.apiKey != "" {
				md := metadata.New(map[string]string{
					APIKeyMetadataKey: tt.apiKey,
				})
				ctx = metadata.NewIncomingContext(ctx, md)
			} else {
				// Test missing metadata
				md := metadata.New(map[string]string{})
				ctx = metadata.NewIncomingContext(ctx, md)
			}

			// Validate
			apiKey, err := validator.ValidateContext(ctx, tt.requiredRole)

			// Check error
			if tt.wantErr != nil {
				assert.ErrorIs(t, err, tt.wantErr)
				assert.Nil(t, apiKey)
			} else {
				require.NoError(t, err)
				require.NotNil(t, apiKey)
				assert.Equal(t, tt.wantKey.Key, apiKey.Key)
				assert.Equal(t, tt.wantKey.Role, apiKey.Role)
			}
		})
	}
}

func TestValidator_DisabledAuth(t *testing.T) {
	config := Config{
		Enabled: false,
		APIKeys: []APIKey{
			{
				Key:         "test-key",
				Role:        RoleHunter,
				Description: "Test key",
			},
		},
	}

	validator := NewValidator(config)

	// When auth is disabled, any context should pass
	ctx := context.Background()

	apiKey, err := validator.ValidateContext(ctx, RoleHunter)
	assert.NoError(t, err)
	assert.Nil(t, apiKey)
}

func TestValidator_UpdateConfig(t *testing.T) {
	initialConfig := Config{
		Enabled: true,
		APIKeys: []APIKey{
			{
				Key:         "old-key",
				Role:        RoleHunter,
				Description: "Old key",
			},
		},
	}

	validator := NewValidator(initialConfig)

	// Validate with old key
	ctx := metadata.NewIncomingContext(
		context.Background(),
		metadata.New(map[string]string{APIKeyMetadataKey: "old-key"}),
	)
	apiKey, err := validator.ValidateContext(ctx, RoleHunter)
	require.NoError(t, err)
	assert.NotNil(t, apiKey)

	// Update config
	newConfig := Config{
		Enabled: true,
		APIKeys: []APIKey{
			{
				Key:         "new-key",
				Role:        RoleHunter,
				Description: "New key",
			},
		},
	}
	validator.UpdateConfig(newConfig)

	// Old key should no longer work
	_, err = validator.ValidateContext(ctx, RoleHunter)
	assert.ErrorIs(t, err, ErrInvalidAPIKey)

	// New key should work
	ctx = metadata.NewIncomingContext(
		context.Background(),
		metadata.New(map[string]string{APIKeyMetadataKey: "new-key"}),
	)
	apiKey, err = validator.ValidateContext(ctx, RoleHunter)
	require.NoError(t, err)
	assert.NotNil(t, apiKey)
}

func TestValidator_NoMetadata(t *testing.T) {
	config := Config{
		Enabled: true,
		APIKeys: []APIKey{
			{
				Key:         "test-key",
				Role:        RoleHunter,
				Description: "Test key",
			},
		},
	}

	validator := NewValidator(config)

	// Context without metadata
	ctx := context.Background()

	_, err := validator.ValidateContext(ctx, RoleHunter)
	assert.ErrorIs(t, err, ErrMissingAPIKey)
}

func TestHasRole(t *testing.T) {
	tests := []struct {
		name       string
		provided   Role
		required   Role
		shouldPass bool
	}{
		{
			name:       "exact match hunter",
			provided:   RoleHunter,
			required:   RoleHunter,
			shouldPass: true,
		},
		{
			name:       "exact match subscriber",
			provided:   RoleSubscriber,
			required:   RoleSubscriber,
			shouldPass: true,
		},
		{
			name:       "admin for hunter",
			provided:   RoleAdmin,
			required:   RoleHunter,
			shouldPass: true,
		},
		{
			name:       "admin for subscriber",
			provided:   RoleAdmin,
			required:   RoleSubscriber,
			shouldPass: true,
		},
		{
			name:       "hunter for subscriber",
			provided:   RoleHunter,
			required:   RoleSubscriber,
			shouldPass: false,
		},
		{
			name:       "subscriber for hunter",
			provided:   RoleSubscriber,
			required:   RoleHunter,
			shouldPass: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := hasRole(tt.provided, tt.required)
			assert.Equal(t, tt.shouldPass, result)
		})
	}
}

func TestMaskAPIKey(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "long key",
			input:    "hunter-key-12345678901234567890",
			expected: "hunter-k****",
		},
		{
			name:     "short key",
			input:    "short",
			expected: "****",
		},
		{
			name:     "8 char key",
			input:    "12345678",
			expected: "****",
		},
		{
			name:     "9 char key",
			input:    "123456789",
			expected: "12345678****",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := maskAPIKey(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGenerateAPIKey(t *testing.T) {
	// Generate a key
	key1, err := GenerateAPIKey()
	require.NoError(t, err)

	// Should be 44 characters (32 bytes base64 encoded with padding)
	assert.Len(t, key1, 44)

	// Generate another key - should be different
	key2, err := GenerateAPIKey()
	require.NoError(t, err)
	assert.NotEqual(t, key1, key2)

	// Should be valid URL-safe base64 (includes = padding)
	assert.Regexp(t, `^[A-Za-z0-9_=-]+$`, key1)
}
