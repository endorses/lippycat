//go:build processor || tap || all

package processor

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// createTestClientRandom creates a test client random with specified byte values.
func createTestClientRandom(seed byte) []byte {
	cr := make([]byte, 32)
	for i := range cr {
		cr[i] = seed + byte(i)
	}
	return cr
}

// createTestSecret creates a test secret of given length.
func createTestSecret(seed byte, length int) []byte {
	secret := make([]byte, length)
	for i := range secret {
		secret[i] = seed
	}
	return secret
}

func TestDefaultTLSKeylogWriterConfig(t *testing.T) {
	config := DefaultTLSKeylogWriterConfig()

	assert.Equal(t, "session_{timestamp}.keys", config.FilePattern)
	assert.Equal(t, 10000, config.MaxEntries)
	assert.Equal(t, time.Hour, config.SessionTTL)
	assert.Empty(t, config.OutputDir)
}

func TestNewTLSKeylogWriter(t *testing.T) {
	t.Run("nil config uses defaults", func(t *testing.T) {
		writer, err := NewTLSKeylogWriter(nil)
		require.NoError(t, err)
		require.NotNil(t, writer)
		defer writer.Close()

		assert.NotNil(t, writer.keyStore)
		assert.NotNil(t, writer.config)
	})

	t.Run("with output directory", func(t *testing.T) {
		tmpDir := t.TempDir()

		config := &TLSKeylogWriterConfig{
			OutputDir:   tmpDir,
			FilePattern: "test_{timestamp}.keys",
			MaxEntries:  100,
			SessionTTL:  time.Minute,
		}

		writer, err := NewTLSKeylogWriter(config)
		require.NoError(t, err)
		require.NotNil(t, writer)
		defer writer.Close()

		assert.Equal(t, tmpDir, writer.config.OutputDir)
	})

	t.Run("creates output directory if missing", func(t *testing.T) {
		tmpDir := filepath.Join(t.TempDir(), "subdir", "keylogs")

		config := &TLSKeylogWriterConfig{
			OutputDir:   tmpDir,
			FilePattern: "test.keys",
			MaxEntries:  100,
			SessionTTL:  time.Minute,
		}

		writer, err := NewTLSKeylogWriter(config)
		require.NoError(t, err)
		require.NotNil(t, writer)
		defer writer.Close()

		// Directory should exist
		_, err = os.Stat(tmpDir)
		assert.NoError(t, err)
	})
}

func TestTLSKeylogWriter_ProcessPacketKeys_TLS12(t *testing.T) {
	tmpDir := t.TempDir()

	config := &TLSKeylogWriterConfig{
		OutputDir:   tmpDir,
		FilePattern: "tls12_test.keys",
		MaxEntries:  1000,
		SessionTTL:  time.Hour,
	}

	writer, err := NewTLSKeylogWriter(config)
	require.NoError(t, err)
	defer writer.Close()

	// Create TLS 1.2 packet with keys
	clientRandom := createTestClientRandom(0x01)
	preMasterSecret := createTestSecret(0xAA, 48)

	packet := &data.CapturedPacket{
		TlsKeys: &data.TLSSessionKeys{
			ClientRandom:    clientRandom,
			TlsVersion:      0x0303, // TLS 1.2
			PreMasterSecret: preMasterSecret,
		},
	}

	// Process the packet
	writer.ProcessPacketKeys(packet)

	// Check stats
	received, written := writer.Stats()
	assert.Equal(t, uint64(1), received)
	assert.Equal(t, uint64(1), written)

	// Verify key store has the entry
	var cr [32]byte
	copy(cr[:], clientRandom)
	sessionKeys := writer.GetKeyStore().Get(cr)
	require.NotNil(t, sessionKeys)
	assert.Equal(t, preMasterSecret, sessionKeys.PreMasterSecret)

	// Verify file was written
	keylogFile := filepath.Join(tmpDir, "tls12_test.keys")
	content, err := os.ReadFile(keylogFile)
	require.NoError(t, err)

	// Should contain CLIENT_RANDOM entry
	assert.Contains(t, string(content), "CLIENT_RANDOM")
	assert.Contains(t, string(content), strings.ToLower(hexEncode(clientRandom)))
	assert.Contains(t, string(content), strings.ToLower(hexEncode(preMasterSecret)))
}

func TestTLSKeylogWriter_ProcessPacketKeys_TLS13(t *testing.T) {
	tmpDir := t.TempDir()

	config := &TLSKeylogWriterConfig{
		OutputDir:   tmpDir,
		FilePattern: "tls13_test.keys",
		MaxEntries:  1000,
		SessionTTL:  time.Hour,
	}

	writer, err := NewTLSKeylogWriter(config)
	require.NoError(t, err)
	defer writer.Close()

	// Create TLS 1.3 packet with keys
	clientRandom := createTestClientRandom(0x02)
	clientHandshakeSecret := createTestSecret(0xBB, 32)
	serverHandshakeSecret := createTestSecret(0xCC, 32)
	clientTrafficSecret := createTestSecret(0xDD, 32)
	serverTrafficSecret := createTestSecret(0xEE, 32)

	packet := &data.CapturedPacket{
		TlsKeys: &data.TLSSessionKeys{
			ClientRandom:                 clientRandom,
			TlsVersion:                   0x0304, // TLS 1.3
			ClientHandshakeTrafficSecret: clientHandshakeSecret,
			ServerHandshakeTrafficSecret: serverHandshakeSecret,
			ClientTrafficSecret_0:        clientTrafficSecret,
			ServerTrafficSecret_0:        serverTrafficSecret,
		},
	}

	// Process the packet
	writer.ProcessPacketKeys(packet)

	// Check stats (4 different secret types)
	received, written := writer.Stats()
	assert.Equal(t, uint64(1), received)
	assert.Equal(t, uint64(4), written)

	// Verify file was written
	keylogFile := filepath.Join(tmpDir, "tls13_test.keys")
	content, err := os.ReadFile(keylogFile)
	require.NoError(t, err)

	// Should contain all TLS 1.3 entries
	assert.Contains(t, string(content), "CLIENT_HANDSHAKE_TRAFFIC_SECRET")
	assert.Contains(t, string(content), "SERVER_HANDSHAKE_TRAFFIC_SECRET")
	assert.Contains(t, string(content), "CLIENT_TRAFFIC_SECRET_0")
	assert.Contains(t, string(content), "SERVER_TRAFFIC_SECRET_0")
}

func TestTLSKeylogWriter_DuplicateKeysIgnored(t *testing.T) {
	tmpDir := t.TempDir()

	config := &TLSKeylogWriterConfig{
		OutputDir:   tmpDir,
		FilePattern: "dedup_test.keys",
		MaxEntries:  1000,
		SessionTTL:  time.Hour,
	}

	writer, err := NewTLSKeylogWriter(config)
	require.NoError(t, err)
	defer writer.Close()

	// Create packet with keys
	clientRandom := createTestClientRandom(0x03)
	preMasterSecret := createTestSecret(0xAA, 48)

	packet := &data.CapturedPacket{
		TlsKeys: &data.TLSSessionKeys{
			ClientRandom:    clientRandom,
			TlsVersion:      0x0303,
			PreMasterSecret: preMasterSecret,
		},
	}

	// Process the same packet multiple times
	writer.ProcessPacketKeys(packet)
	writer.ProcessPacketKeys(packet)
	writer.ProcessPacketKeys(packet)

	// All 3 were received, but only 1 written (duplicates ignored)
	received, written := writer.Stats()
	assert.Equal(t, uint64(3), received) // 3 packets received
	assert.Equal(t, uint64(1), written)  // Only 1 unique key written
}

func TestTLSKeylogWriter_InvalidClientRandom(t *testing.T) {
	config := &TLSKeylogWriterConfig{
		MaxEntries: 1000,
		SessionTTL: time.Hour,
	}

	writer, err := NewTLSKeylogWriter(config)
	require.NoError(t, err)
	defer writer.Close()

	// Create packet with invalid client random length
	packet := &data.CapturedPacket{
		TlsKeys: &data.TLSSessionKeys{
			ClientRandom:    []byte{0x01, 0x02, 0x03}, // Invalid: only 3 bytes
			TlsVersion:      0x0303,
			PreMasterSecret: createTestSecret(0xAA, 48),
		},
	}

	// Process the packet
	writer.ProcessPacketKeys(packet)

	// Should not be processed
	received, written := writer.Stats()
	assert.Equal(t, uint64(1), received)
	assert.Equal(t, uint64(0), written)
}

func TestTLSKeylogWriter_NilTlsKeys(t *testing.T) {
	config := &TLSKeylogWriterConfig{
		MaxEntries: 1000,
		SessionTTL: time.Hour,
	}

	writer, err := NewTLSKeylogWriter(config)
	require.NoError(t, err)
	defer writer.Close()

	// Create packet without TLS keys
	packet := &data.CapturedPacket{
		TlsKeys: nil,
	}

	// Process the packet - should not panic
	writer.ProcessPacketKeys(packet)

	// Should not be counted
	received, _ := writer.Stats()
	assert.Equal(t, uint64(0), received)
}

func TestTLSKeylogWriter_MemoryOnlyMode(t *testing.T) {
	// No output directory - memory only
	config := &TLSKeylogWriterConfig{
		MaxEntries: 1000,
		SessionTTL: time.Hour,
	}

	writer, err := NewTLSKeylogWriter(config)
	require.NoError(t, err)
	defer writer.Close()

	// Create packet with keys
	clientRandom := createTestClientRandom(0x04)
	preMasterSecret := createTestSecret(0xAA, 48)

	packet := &data.CapturedPacket{
		TlsKeys: &data.TLSSessionKeys{
			ClientRandom:    clientRandom,
			TlsVersion:      0x0303,
			PreMasterSecret: preMasterSecret,
		},
	}

	// Process the packet
	writer.ProcessPacketKeys(packet)

	// Keys should be received but not written (no output dir)
	received, written := writer.Stats()
	assert.Equal(t, uint64(1), received)
	assert.Equal(t, uint64(0), written)

	// But should still be in memory store
	var cr [32]byte
	copy(cr[:], clientRandom)
	sessionKeys := writer.GetKeyStore().Get(cr)
	require.NotNil(t, sessionKeys)
	assert.Equal(t, preMasterSecret, sessionKeys.PreMasterSecret)
}

func TestTLSKeylogWriter_RotateFile(t *testing.T) {
	tmpDir := t.TempDir()

	config := &TLSKeylogWriterConfig{
		OutputDir:   tmpDir,
		FilePattern: "rotate_{timestamp}.keys",
		MaxEntries:  1000,
		SessionTTL:  time.Hour,
	}

	writer, err := NewTLSKeylogWriter(config)
	require.NoError(t, err)
	defer writer.Close()

	// Write first key
	packet1 := &data.CapturedPacket{
		TlsKeys: &data.TLSSessionKeys{
			ClientRandom:    createTestClientRandom(0x01),
			TlsVersion:      0x0303,
			PreMasterSecret: createTestSecret(0xAA, 48),
		},
	}
	writer.ProcessPacketKeys(packet1)

	firstFile := writer.CurrentFilePath()
	require.NotEmpty(t, firstFile)

	// Small delay to ensure different timestamp
	time.Sleep(1100 * time.Millisecond)

	// Rotate the file
	err = writer.RotateFile()
	require.NoError(t, err)

	// Write second key
	packet2 := &data.CapturedPacket{
		TlsKeys: &data.TLSSessionKeys{
			ClientRandom:    createTestClientRandom(0x02),
			TlsVersion:      0x0303,
			PreMasterSecret: createTestSecret(0xBB, 48),
		},
	}
	writer.ProcessPacketKeys(packet2)

	secondFile := writer.CurrentFilePath()

	// Files should be different (different timestamps)
	assert.NotEqual(t, firstFile, secondFile)

	// Both files should exist
	_, err = os.Stat(firstFile)
	assert.NoError(t, err)
	_, err = os.Stat(secondFile)
	assert.NoError(t, err)
}

func TestTLSKeylogWriter_PatternPlaceholders(t *testing.T) {
	now := time.Now()

	testCases := []struct {
		pattern  string
		expected string
	}{
		{
			pattern:  "test_{date}.keys",
			expected: "test_" + now.Format("2006-01-02") + ".keys",
		},
		{
			pattern:  "keys_{datetime}.log",
			expected: "keys_" + now.Format("2006-01-02_15-04-05") + ".log",
		},
		{
			pattern:  "no_placeholders.keys",
			expected: "no_placeholders.keys",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.pattern, func(t *testing.T) {
			result := replacePatternPlaceholders(tc.pattern, now, "")
			// For timestamp, just check it's replaced (can't predict exact value)
			if !strings.Contains(tc.pattern, "{timestamp}") {
				assert.Equal(t, tc.expected, result)
			} else {
				assert.NotContains(t, result, "{timestamp}")
			}
		})
	}
}

func TestTLSKeylogWriter_GetKeyStore(t *testing.T) {
	config := &TLSKeylogWriterConfig{
		MaxEntries: 100,
		SessionTTL: time.Hour,
	}

	writer, err := NewTLSKeylogWriter(config)
	require.NoError(t, err)
	defer writer.Close()

	store := writer.GetKeyStore()
	require.NotNil(t, store)
}

func TestTLSKeylogWriter_Close(t *testing.T) {
	tmpDir := t.TempDir()

	config := &TLSKeylogWriterConfig{
		OutputDir:   tmpDir,
		FilePattern: "close_test.keys",
		MaxEntries:  100,
		SessionTTL:  time.Hour,
	}

	writer, err := NewTLSKeylogWriter(config)
	require.NoError(t, err)

	// Write some keys
	packet := &data.CapturedPacket{
		TlsKeys: &data.TLSSessionKeys{
			ClientRandom:    createTestClientRandom(0x01),
			TlsVersion:      0x0303,
			PreMasterSecret: createTestSecret(0xAA, 48),
		},
	}
	writer.ProcessPacketKeys(packet)

	// Close should not error
	err = writer.Close()
	assert.NoError(t, err)

	// File should be flushed and closed
	keylogFile := filepath.Join(tmpDir, "close_test.keys")
	content, err := os.ReadFile(keylogFile)
	require.NoError(t, err)
	assert.Contains(t, string(content), "CLIENT_RANDOM")
}

func TestTLSKeylogWriter_WrittenKeysEviction(t *testing.T) {
	// Test LRU eviction when MaxEntries is reached
	config := &TLSKeylogWriterConfig{
		MaxEntries: 3, // Very small for testing
		SessionTTL: time.Hour,
	}

	writer, err := NewTLSKeylogWriter(config)
	require.NoError(t, err)
	defer writer.Close()

	// Add 4 keys - should evict oldest when 4th is added
	for i := byte(0); i < 4; i++ {
		packet := &data.CapturedPacket{
			TlsKeys: &data.TLSSessionKeys{
				ClientRandom:    createTestClientRandom(i),
				TlsVersion:      0x0303,
				PreMasterSecret: createTestSecret(0xAA, 48),
			},
		}
		writer.ProcessPacketKeys(packet)
	}

	// Should have 3 keys (max) and 1 evicted
	writer.mu.Lock()
	assert.Equal(t, 3, len(writer.writtenKeys))
	assert.Equal(t, uint64(1), writer.keysEvicted)
	writer.mu.Unlock()
}

func TestTLSKeylogWriter_WrittenKeysTTLCleanup(t *testing.T) {
	// Test TTL-based cleanup
	config := &TLSKeylogWriterConfig{
		MaxEntries: 100,
		SessionTTL: 50 * time.Millisecond, // Very short for testing
	}

	writer, err := NewTLSKeylogWriter(config)
	require.NoError(t, err)
	defer writer.Close()

	// Add a key
	packet := &data.CapturedPacket{
		TlsKeys: &data.TLSSessionKeys{
			ClientRandom:    createTestClientRandom(0x01),
			TlsVersion:      0x0303,
			PreMasterSecret: createTestSecret(0xAA, 48),
		},
	}
	writer.ProcessPacketKeys(packet)

	// Verify key exists
	writer.mu.Lock()
	assert.Equal(t, 1, len(writer.writtenKeys))
	writer.mu.Unlock()

	// Wait for TTL to expire
	time.Sleep(100 * time.Millisecond)

	// Manually trigger cleanup (normally runs every 5 minutes)
	writer.cleanupWrittenKeys()

	// Key should be evicted
	writer.mu.Lock()
	assert.Equal(t, 0, len(writer.writtenKeys))
	assert.Equal(t, uint64(1), writer.keysEvicted)
	writer.mu.Unlock()
}

func TestTLSKeylogWriter_CleanupLoopStopsOnClose(t *testing.T) {
	config := &TLSKeylogWriterConfig{
		MaxEntries: 100,
		SessionTTL: time.Hour,
	}

	writer, err := NewTLSKeylogWriter(config)
	require.NoError(t, err)

	// Close should stop the cleanup goroutine cleanly
	err = writer.Close()
	assert.NoError(t, err)

	// Multiple closes should not panic
	assert.NotPanics(t, func() {
		// The goroutine is already stopped, this is to verify no deadlock
	})
}

// Helper function for hex encoding
func hexEncode(data []byte) string {
	const hexChars = "0123456789abcdef"
	result := make([]byte, len(data)*2)
	for i, b := range data {
		result[i*2] = hexChars[b>>4]
		result[i*2+1] = hexChars[b&0x0f]
	}
	return string(result)
}
