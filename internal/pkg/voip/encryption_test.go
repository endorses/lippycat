package voip

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEncryptionConfig(t *testing.T) {
	// Reset viper for clean test environment
	viper.Reset()

	// Test default configuration
	config := getEncryptionConfig()
	assert.False(t, config.Enabled, "Encryption should be disabled by default")
	assert.Equal(t, "", config.KeyFile, "Key file should be empty by default")
	assert.Equal(t, "aes-256-gcm", config.Algorithm, "Default algorithm should be AES-256-GCM")
	assert.Equal(t, "pbkdf2", config.KeyDerive, "Default key derivation should be PBKDF2")
	assert.Equal(t, DefaultIters, config.Iterations, "Default iterations should match constant")

	// Test custom configuration
	viper.Set("voip.encryption.enabled", true)
	viper.Set("voip.encryption.key_file", "/tmp/test.key")
	viper.Set("voip.encryption.algorithm", "aes-256-gcm")
	viper.Set("voip.encryption.pbkdf2_iterations", 50000)

	config = getEncryptionConfig()
	assert.True(t, config.Enabled)
	assert.Equal(t, "/tmp/test.key", config.KeyFile)
	assert.Equal(t, "aes-256-gcm", config.Algorithm)
	assert.Equal(t, 50000, config.Iterations)
}

func TestValidateEncryptionConfig(t *testing.T) {
	tests := []struct {
		name          string
		enabled       bool
		keyFile       string
		algorithm     string
		keyDerive     string
		iterations    int
		shouldSucceed bool
		errorContains string
	}{
		{
			name:          "Disabled encryption",
			enabled:       false,
			shouldSucceed: true,
		},
		{
			name:          "Valid configuration",
			enabled:       true,
			keyFile:       "/tmp/test-valid.key",
			algorithm:     "aes-256-gcm",
			keyDerive:     "pbkdf2",
			iterations:    100000,
			shouldSucceed: true,
		},
		{
			name:          "Missing key file",
			enabled:       true,
			keyFile:       "",
			algorithm:     "aes-256-gcm",
			keyDerive:     "pbkdf2",
			iterations:    100000,
			shouldSucceed: false,
			errorContains: "no key file specified",
		},
		{
			name:          "Unsupported algorithm",
			enabled:       true,
			keyFile:       "/tmp/test-algo.key",
			algorithm:     "des",
			keyDerive:     "pbkdf2",
			iterations:    100000,
			shouldSucceed: false,
			errorContains: "unsupported encryption algorithm",
		},
		{
			name:          "Unsupported key derivation",
			enabled:       true,
			keyFile:       "/tmp/test-kdf.key",
			algorithm:     "aes-256-gcm",
			keyDerive:     "scrypt",
			iterations:    100000,
			shouldSucceed: false,
			errorContains: "unsupported key derivation",
		},
		{
			name:          "Insufficient iterations",
			enabled:       true,
			keyFile:       "/tmp/test-iter.key",
			algorithm:     "aes-256-gcm",
			keyDerive:     "pbkdf2",
			iterations:    1000,
			shouldSucceed: false,
			errorContains: "iterations too low",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset viper
			viper.Reset()

			// Set configuration
			viper.Set("voip.encryption.enabled", tt.enabled)
			viper.Set("voip.encryption.key_file", tt.keyFile)
			viper.Set("voip.encryption.algorithm", tt.algorithm)
			viper.Set("voip.encryption.key_derive", tt.keyDerive)
			viper.Set("voip.encryption.pbkdf2_iterations", tt.iterations)

			err := ValidateEncryptionConfig()

			if tt.shouldSucceed {
				assert.NoError(t, err, "Validation should succeed")
			} else {
				require.Error(t, err, "Validation should fail")
				assert.Contains(t, err.Error(), tt.errorContains,
					"Error should contain expected text")
			}
		})
	}
}

func TestKeyGeneration(t *testing.T) {
	tempDir := t.TempDir()
	keyFile := filepath.Join(tempDir, "test.key")

	// Test key generation when file doesn't exist
	key1, err := readOrGenerateKey(keyFile)
	require.NoError(t, err, "Should generate key successfully")
	assert.Len(t, key1, AESKeySize, "Key should be correct length")

	// Verify key file was created
	assert.FileExists(t, keyFile, "Key file should be created")

	// Verify file permissions
	info, err := os.Stat(keyFile)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), info.Mode().Perm(), "Key file should have restrictive permissions")

	// Test reading existing key
	key2, err := readOrGenerateKey(keyFile)
	require.NoError(t, err, "Should read existing key successfully")
	assert.Equal(t, key1, key2, "Should read the same key that was generated")
}

func TestKeyGenerationErrors(t *testing.T) {
	tests := []struct {
		name          string
		keyFile       string
		setup         func(string) error
		shouldSucceed bool
		errorContains string
	}{
		{
			name:          "Empty key file path",
			keyFile:       "",
			shouldSucceed: false,
			errorContains: "not specified",
		},
		{
			name:    "Insufficient key material",
			keyFile: "/tmp/short-key.key",
			setup: func(path string) error {
				return os.WriteFile(path, []byte("short"), 0600)
			},
			shouldSucceed: false,
			errorContains: "insufficient key material",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clean up any existing file
			if tt.keyFile != "" {
				os.Remove(tt.keyFile)
			}

			// Run setup if provided
			if tt.setup != nil {
				err := tt.setup(tt.keyFile)
				require.NoError(t, err, "Setup should succeed")
			}

			_, err := readOrGenerateKey(tt.keyFile)

			if tt.shouldSucceed {
				assert.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorContains)
			}

			// Cleanup
			if tt.keyFile != "" {
				os.Remove(tt.keyFile)
			}
		})
	}
}

func TestEncryptedPCAPWriter(t *testing.T) {
	tempDir := t.TempDir()
	keyFile := filepath.Join(tempDir, "test.key")
	pcapFile := filepath.Join(tempDir, "test.pcap")

	// Configure encryption
	viper.Reset()
	viper.Set("voip.encryption.enabled", true)
	viper.Set("voip.encryption.key_file", keyFile)
	viper.Set("voip.encryption.algorithm", "aes-256-gcm")

	// Test creating encrypted writer
	writer, err := NewEncryptedPCAPWriter(pcapFile)
	require.NoError(t, err, "Should create encrypted writer successfully")
	defer writer.Close()

	// Test writing data
	testData1 := []byte("test packet data 1")
	testData2 := []byte("test packet data 2 with different content")

	err = writer.WriteData(testData1)
	assert.NoError(t, err, "Should write first data block successfully")

	err = writer.WriteData(testData2)
	assert.NoError(t, err, "Should write second data block successfully")

	// Close writer
	err = writer.Close()
	assert.NoError(t, err, "Should close writer successfully")

	// Verify encrypted file exists and has content
	encryptedFile := pcapFile + ".enc"
	assert.FileExists(t, encryptedFile, "Encrypted file should exist")

	encryptedData, err := os.ReadFile(encryptedFile)
	require.NoError(t, err, "Should read encrypted file")
	assert.Greater(t, len(encryptedData), 0, "Encrypted file should have content")

	// Verify the data is encrypted (should not contain original plaintext)
	assert.NotContains(t, string(encryptedData), string(testData1),
		"Encrypted file should not contain plaintext")
	assert.NotContains(t, string(encryptedData), string(testData2),
		"Encrypted file should not contain plaintext")
}

func TestEncryptedPCAPWriterDisabled(t *testing.T) {
	tempDir := t.TempDir()
	pcapFile := filepath.Join(tempDir, "test.pcap")

	// Configure encryption as disabled
	viper.Reset()
	viper.Set("voip.encryption.enabled", false)

	// Test creating encrypted writer when disabled
	writer, err := NewEncryptedPCAPWriter(pcapFile)
	assert.Error(t, err, "Should fail when encryption is disabled")
	assert.Nil(t, writer, "Writer should be nil when encryption is disabled")
	assert.Contains(t, err.Error(), "not enabled", "Error should mention encryption not enabled")
}

func TestDecryptPCAPFile(t *testing.T) {
	tempDir := t.TempDir()
	keyFile := filepath.Join(tempDir, "decrypt-test.key")
	pcapFile := filepath.Join(tempDir, "decrypt-test.pcap")
	outputFile := filepath.Join(tempDir, "decrypted-output.pcap")

	// Configure encryption
	viper.Reset()
	viper.Set("voip.encryption.enabled", true)
	viper.Set("voip.encryption.key_file", keyFile)
	viper.Set("voip.encryption.algorithm", "aes-256-gcm")

	// Create test data
	testData1 := []byte("PCAP packet data block 1")
	testData2 := []byte("PCAP packet data block 2 with more content")
	testData3 := []byte("Final PCAP packet data block")

	// Encrypt test data
	writer, err := NewEncryptedPCAPWriter(pcapFile)
	require.NoError(t, err, "Should create encrypted writer")

	err = writer.WriteData(testData1)
	require.NoError(t, err, "Should write test data 1")

	err = writer.WriteData(testData2)
	require.NoError(t, err, "Should write test data 2")

	err = writer.WriteData(testData3)
	require.NoError(t, err, "Should write test data 3")

	err = writer.Close()
	require.NoError(t, err, "Should close writer")

	// Decrypt the file
	encryptedFile := pcapFile + ".enc"
	err = DecryptPCAPFile(encryptedFile, outputFile, keyFile)
	require.NoError(t, err, "Should decrypt file successfully")

	// Verify decrypted content
	decryptedData, err := os.ReadFile(outputFile)
	require.NoError(t, err, "Should read decrypted file")

	// The decrypted file should contain all original data concatenated
	expectedData := append(append(testData1, testData2...), testData3...)
	assert.Equal(t, expectedData, decryptedData, "Decrypted data should match original")
}

func TestDeriveKeyFromPassword(t *testing.T) {
	password := []byte("test-password-123")
	salt := []byte("test-salt-for-key-derivation-32bytes")

	// Test key derivation
	key1 := deriveKeyFromPassword(password, salt, 10000)
	assert.Len(t, key1, AESKeySize, "Derived key should be correct length")

	// Test consistency
	key2 := deriveKeyFromPassword(password, salt, 10000)
	assert.Equal(t, key1, key2, "Key derivation should be deterministic")

	// Test different passwords produce different keys
	differentPassword := []byte("different-password-456")
	key3 := deriveKeyFromPassword(differentPassword, salt, 10000)
	assert.NotEqual(t, key1, key3, "Different passwords should produce different keys")

	// Test different salts produce different keys
	differentSalt := []byte("different-salt-for-testing-32byt")
	key4 := deriveKeyFromPassword(password, differentSalt, 10000)
	assert.NotEqual(t, key1, key4, "Different salts should produce different keys")

	// Test different iteration counts produce different keys
	key5 := deriveKeyFromPassword(password, salt, 20000)
	assert.NotEqual(t, key1, key5, "Different iteration counts should produce different keys")
}

func TestEncryptedPCAPWriterErrorCases(t *testing.T) {
	tempDir := t.TempDir()

	tests := []struct {
		name          string
		algorithm     string
		keyFile       string
		setup         func(string) error
		shouldSucceed bool
		errorContains string
	}{
		{
			name:          "Unsupported algorithm",
			algorithm:     "des",
			keyFile:       filepath.Join(tempDir, "test-des.key"),
			shouldSucceed: false,
			errorContains: "unsupported encryption algorithm",
		},
		{
			name:      "Invalid key file directory",
			algorithm: "aes-256-gcm",
			keyFile:   "/root/impossible/path/key.file", // Assuming test doesn't run as root
			setup: func(path string) error {
				// Try to create a file in a directory we can't access
				return nil
			},
			shouldSucceed: false,
			errorContains: "failed to get encryption key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Configure test
			viper.Reset()
			viper.Set("voip.encryption.enabled", true)
			viper.Set("voip.encryption.key_file", tt.keyFile)
			viper.Set("voip.encryption.algorithm", tt.algorithm)

			if tt.setup != nil {
				err := tt.setup(tt.keyFile)
				require.NoError(t, err, "Setup should succeed")
			}

			pcapFile := filepath.Join(tempDir, "error-test.pcap")
			writer, err := NewEncryptedPCAPWriter(pcapFile)

			if tt.shouldSucceed {
				assert.NoError(t, err)
				if writer != nil {
					writer.Close()
				}
			} else {
				assert.Error(t, err)
				assert.Nil(t, writer)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
			}
		})
	}
}

func TestWriteAfterClose(t *testing.T) {
	tempDir := t.TempDir()
	keyFile := filepath.Join(tempDir, "close-test.key")
	pcapFile := filepath.Join(tempDir, "close-test.pcap")

	// Configure encryption
	viper.Reset()
	viper.Set("voip.encryption.enabled", true)
	viper.Set("voip.encryption.key_file", keyFile)

	// Create writer
	writer, err := NewEncryptedPCAPWriter(pcapFile)
	require.NoError(t, err)

	// Close writer
	err = writer.Close()
	require.NoError(t, err)

	// Try to write after close
	err = writer.WriteData([]byte("test data"))
	assert.Error(t, err, "Should fail to write after close")
	assert.Contains(t, err.Error(), "closed", "Error should mention writer is closed")

	// Multiple closes should be safe
	err = writer.Close()
	assert.NoError(t, err, "Multiple closes should be safe")
}
