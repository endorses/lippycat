package auth

import (
	"errors"
)

// Role defines the type of access granted to an API key.
type Role string

const (
	// RoleHunter allows registering as a hunter and sending packets.
	RoleHunter Role = "hunter"
	// RoleSubscriber allows subscribing to packet streams and topology updates.
	RoleSubscriber Role = "subscriber"
	// RoleAdmin allows all operations (future use).
	RoleAdmin Role = "admin"
)

// APIKey represents a single API key configuration.
type APIKey struct {
	// Key is the actual API key string (should be cryptographically random).
	Key string `yaml:"key" json:"key"`
	// Role defines what this key is authorized to do.
	Role Role `yaml:"role" json:"role"`
	// Description is a human-readable description for auditing.
	Description string `yaml:"description" json:"description"`
}

// Config represents the authentication configuration.
type Config struct {
	// Enabled controls whether API key authentication is required.
	// In production mode (LIPPYCAT_PRODUCTION=true), this is always true.
	Enabled bool `yaml:"enabled" json:"enabled"`
	// APIKeys is the list of valid API keys.
	APIKeys []APIKey `yaml:"api_keys" json:"api_keys"`
}

// Common errors
var (
	// ErrMissingAPIKey is returned when no API key is provided.
	ErrMissingAPIKey = errors.New("missing API key in metadata")
	// ErrInvalidAPIKey is returned when the API key is not recognized.
	ErrInvalidAPIKey = errors.New("invalid API key")
	// ErrInsufficientPermissions is returned when the API key doesn't have the required role.
	ErrInsufficientPermissions = errors.New("insufficient permissions for this operation")
)
