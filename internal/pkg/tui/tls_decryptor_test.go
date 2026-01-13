//go:build tui || all

package tui

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewTLSDecryptor_WithoutKeylog(t *testing.T) {
	// Test creating a decryptor without a keylog file
	decryptor, err := NewTLSDecryptor("")
	require.NoError(t, err)
	require.NotNil(t, decryptor)

	// Verify the session manager was created
	assert.NotNil(t, decryptor.sessionManager)
	assert.NotNil(t, decryptor.keyStore)
	assert.Nil(t, decryptor.keyWatcher) // No watcher when no keylog path

	// Clean up
	decryptor.Stop()
}

func TestNewTLSDecryptor_WithKeylog(t *testing.T) {
	// Create a temporary keylog file
	tmpDir := t.TempDir()
	keylogPath := filepath.Join(tmpDir, "sslkeys.log")

	// Write a sample keylog entry
	keylogContent := "# TLS Key Log\nCLIENT_RANDOM 0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20 aabbccdd\n"
	err := os.WriteFile(keylogPath, []byte(keylogContent), 0600)
	require.NoError(t, err)

	// Create decryptor with keylog file
	decryptor, err := NewTLSDecryptor(keylogPath)
	require.NoError(t, err)
	require.NotNil(t, decryptor)

	// Verify the watcher was created
	assert.NotNil(t, decryptor.keyWatcher)

	// Clean up
	decryptor.Stop()
}

func TestGlobalTLSDecryptor(t *testing.T) {
	// Initially should be nil
	ClearTLSDecryptor()
	assert.Nil(t, GetTLSDecryptor())

	// Create and set a decryptor
	decryptor, err := NewTLSDecryptor("")
	require.NoError(t, err)

	SetTLSDecryptor(decryptor)
	assert.Equal(t, decryptor, GetTLSDecryptor())

	// Clear should stop and remove
	ClearTLSDecryptor()
	assert.Nil(t, GetTLSDecryptor())
}

func TestInitTLSDecryptorFromConfig_Disabled(t *testing.T) {
	// Reset global state
	ClearTLSDecryptor()

	// Ensure decryption is disabled in config
	viper.Set("tui.tls_decryption_enabled", false)

	result := InitTLSDecryptorFromConfig()
	assert.False(t, result)
	assert.Nil(t, GetTLSDecryptor())

	// Clean up viper state
	viper.Set("tui.tls_decryption_enabled", nil)
}

func TestInitTLSDecryptorFromConfig_NoKeylog(t *testing.T) {
	// Reset global state
	ClearTLSDecryptor()

	// Enable decryption but no keylog path
	viper.Set("tui.tls_decryption_enabled", true)
	viper.Set("tui.tls_keylog", "")

	result := InitTLSDecryptorFromConfig()
	assert.False(t, result)
	assert.Nil(t, GetTLSDecryptor())

	// Clean up viper state
	viper.Set("tui.tls_decryption_enabled", nil)
	viper.Set("tui.tls_keylog", nil)
}

func TestGetDecryptedData_NoSession(t *testing.T) {
	decryptor, err := NewTLSDecryptor("")
	require.NoError(t, err)
	defer decryptor.Stop()

	// Query for non-existent flow
	clientData, serverData := decryptor.GetDecryptedData("192.168.1.1", "192.168.1.2", "12345", "443")
	assert.Empty(t, clientData)
	assert.Empty(t, serverData)
}

func TestHasDecryptedData(t *testing.T) {
	decryptor, err := NewTLSDecryptor("")
	require.NoError(t, err)
	defer decryptor.Stop()

	// No data should be available
	result := decryptor.HasDecryptedData("192.168.1.1", "192.168.1.2", "12345", "443")
	assert.False(t, result)
}

func TestExtractTLSPayload(t *testing.T) {
	tests := []struct {
		name     string
		rawData  []byte
		expected bool // Whether TLS payload should be extracted
	}{
		{
			name:     "too short",
			rawData:  make([]byte, 50),
			expected: false,
		},
		{
			name:     "empty",
			rawData:  nil,
			expected: false,
		},
		{
			name: "invalid IP version",
			rawData: func() []byte {
				data := make([]byte, 100)
				// Ethernet (14) + invalid IP version
				data[14] = 0x00 // Invalid IP version
				return data
			}(),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractTLSPayload(tt.rawData)
			if tt.expected {
				assert.NotNil(t, result)
			} else {
				assert.Nil(t, result)
			}
		})
	}
}
