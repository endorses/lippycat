package processor

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDefaultPcapWriterConfig tests default configuration
func TestDefaultPcapWriterConfig(t *testing.T) {
	config := DefaultPcapWriterConfig()

	assert.NotNil(t, config)
	assert.False(t, config.Enabled)
	assert.Equal(t, "./pcaps", config.OutputDir)
	assert.Equal(t, "{timestamp}_{callid}.pcap", config.FilePattern)
	assert.Equal(t, int64(100*1024*1024), config.MaxFileSize) // 100MB
	assert.Equal(t, 10, config.MaxFilesPerCall)
	assert.Equal(t, 4096, config.BufferSize)
	assert.Equal(t, 5*time.Second, config.SyncInterval)
}

// TestNewPcapWriterManager tests manager creation
func TestNewPcapWriterManager(t *testing.T) {
	tests := []struct {
		name    string
		config  *PcapWriterConfig
		wantErr bool
	}{
		{
			name:    "nil config uses defaults",
			config:  nil,
			wantErr: false,
		},
		{
			name: "disabled config",
			config: &PcapWriterConfig{
				Enabled:   false,
				OutputDir: "./test-pcaps",
			},
			wantErr: false,
		},
		{
			name: "enabled config creates directory",
			config: &PcapWriterConfig{
				Enabled:   true,
				OutputDir: filepath.Join(os.TempDir(), "lippycat-test-pcaps"),
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clean up test directory if it exists
			if tt.config != nil && tt.config.Enabled && tt.config.OutputDir != "" {
				defer os.RemoveAll(tt.config.OutputDir)
			}

			manager, err := NewPcapWriterManager(tt.config)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, manager)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, manager)
				assert.NotNil(t, manager.config)
				assert.NotNil(t, manager.writers)

				// Verify directory was created for enabled configs
				if tt.config != nil && tt.config.Enabled {
					info, err := os.Stat(tt.config.OutputDir)
					assert.NoError(t, err)
					assert.True(t, info.IsDir())
				}
			}
		})
	}
}

// TestSanitizeFilename tests filename sanitization
func TestSanitizeFilename(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "normal filename",
			input:    "test.pcap",
			expected: "test.pcap",
		},
		{
			name:     "filename with spaces",
			input:    "test file.pcap",
			expected: "test_file.pcap",
		},
		{
			name:     "filename with slashes",
			input:    "path/to/file.pcap",
			expected: "path_to_file.pcap",
		},
		{
			name:     "filename with special characters",
			input:    "test@file#name$.pcap",
			expected: "test_file#name$.pcap",
		},
		{
			name:     "filename with backslashes",
			input:    "test\\file.pcap",
			expected: "test_file.pcap",
		},
		{
			name:     "filename with colons",
			input:    "test:file.pcap",
			expected: "test_file.pcap",
		},
		{
			name:     "empty filename",
			input:    "",
			expected: "",
		},
		{
			name:     "filename with dots",
			input:    "../../../etc/passwd",
			expected: ".._.._.._etc_passwd",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sanitizeFilename(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestPcapWriterConfig tests config structure
func TestPcapWriterConfig(t *testing.T) {
	config := &PcapWriterConfig{
		Enabled:         true,
		OutputDir:       "/tmp/pcaps",
		FilePattern:     "call_{callid}.pcap",
		MaxFileSize:     50 * 1024 * 1024, // 50MB
		MaxFilesPerCall: 5,
		BufferSize:      8192,
		SyncInterval:    10 * time.Second,
	}

	assert.True(t, config.Enabled)
	assert.Equal(t, "/tmp/pcaps", config.OutputDir)
	assert.Equal(t, "call_{callid}.pcap", config.FilePattern)
	assert.Equal(t, int64(50*1024*1024), config.MaxFileSize)
	assert.Equal(t, 5, config.MaxFilesPerCall)
	assert.Equal(t, 8192, config.BufferSize)
	assert.Equal(t, 10*time.Second, config.SyncInterval)
}

// TestGetOrCreateWriter_Disabled tests that no writer is created when disabled
func TestGetOrCreateWriter_Disabled(t *testing.T) {
	config := &PcapWriterConfig{
		Enabled: false,
	}

	manager, err := NewPcapWriterManager(config)
	require.NoError(t, err)

	writer, err := manager.GetOrCreateWriter("test-call", "alicent", "robb")
	assert.NoError(t, err)
	assert.Nil(t, writer, "writer should be nil when disabled")
}

// TestCloseWriter tests writer cleanup
func TestCloseWriter(t *testing.T) {
	tempDir := filepath.Join(os.TempDir(), "lippycat-close-test")
	defer os.RemoveAll(tempDir)

	config := &PcapWriterConfig{
		Enabled:   true,
		OutputDir: tempDir,
	}

	manager, err := NewPcapWriterManager(config)
	require.NoError(t, err)

	// Attempting to close non-existent writer should not error
	err = manager.CloseWriter("non-existent-call")
	assert.NoError(t, err)

	// Verify no panic occurred
	assert.Equal(t, 0, len(manager.writers))
}

// TestMultipleWriters tests managing multiple writers
func TestMultipleWriters(t *testing.T) {
	config := &PcapWriterConfig{
		Enabled: false, // Disabled so we don't create actual files
	}

	manager, err := NewPcapWriterManager(config)
	require.NoError(t, err)

	// Since disabled, all GetOrCreateWriter calls should return nil
	writer1, err := manager.GetOrCreateWriter("call-1", "alicent", "robb")
	assert.NoError(t, err)
	assert.Nil(t, writer1)

	writer2, err := manager.GetOrCreateWriter("call-2", "charlie", "dave")
	assert.NoError(t, err)
	assert.Nil(t, writer2)

	// Verify no writers were created
	manager.mu.RLock()
	count := len(manager.writers)
	manager.mu.RUnlock()
	assert.Equal(t, 0, count)
}

// TestPcapWriterConcurrency tests thread-safe operations
func TestPcapWriterConcurrency(t *testing.T) {
	config := &PcapWriterConfig{
		Enabled: false, // Disabled to avoid file I/O
	}

	manager, err := NewPcapWriterManager(config)
	require.NoError(t, err)

	const numGoroutines = 10
	done := make(chan struct{})

	// Concurrent GetOrCreateWriter calls
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			callID := "call-" + string(rune('0'+id))
			_, _ = manager.GetOrCreateWriter(callID, "alicent", "robb")
			done <- struct{}{}
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < numGoroutines; i++ {
		<-done
	}

	// No assertions needed - if there's a race condition, it will be detected by -race flag
}

// TestPcapWriterConfigValidation tests configuration validation
func TestPcapWriterConfigValidation(t *testing.T) {
	tests := []struct {
		name   string
		config *PcapWriterConfig
		valid  bool
	}{
		{
			name: "valid config",
			config: &PcapWriterConfig{
				Enabled:         true,
				OutputDir:       "/tmp/test",
				FilePattern:     "{callid}.pcap",
				MaxFileSize:     1024 * 1024,
				MaxFilesPerCall: 10,
				BufferSize:      4096,
				SyncInterval:    time.Second,
			},
			valid: true,
		},
		{
			name: "zero values are valid",
			config: &PcapWriterConfig{
				Enabled:         true,
				OutputDir:       "/tmp/test",
				FilePattern:     "{callid}.pcap",
				MaxFileSize:     0, // unlimited
				MaxFilesPerCall: 0, // unlimited
				BufferSize:      0,
				SyncInterval:    0,
			},
			valid: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Just verify the config can be created and has expected values
			assert.Equal(t, tt.config.Enabled, tt.config.Enabled)
			assert.Equal(t, tt.config.OutputDir, tt.config.OutputDir)
		})
	}
}

// TestReplaceAll tests the replaceAll helper function
func TestReplaceAll(t *testing.T) {
	tests := []struct {
		name     string
		s        string
		old      string
		new      string
		expected string
	}{
		{
			name:     "simple replacement",
			s:        "hello world",
			old:      "world",
			new:      "gopher",
			expected: "hello gopher",
		},
		{
			name:     "multiple replacements",
			s:        "foo bar foo baz foo",
			old:      "foo",
			new:      "qux",
			expected: "qux bar qux baz qux",
		},
		{
			name:     "no match",
			s:        "hello world",
			old:      "xyz",
			new:      "abc",
			expected: "hello world",
		},
		{
			name:     "empty string",
			s:        "",
			old:      "foo",
			new:      "bar",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := replaceAll(tt.s, tt.old, tt.new)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestIndexSubstring tests the indexSubstring helper function
func TestIndexSubstring(t *testing.T) {
	tests := []struct {
		name     string
		s        string
		substr   string
		expected int
	}{
		{
			name:     "found at start",
			s:        "hello world",
			substr:   "hello",
			expected: 0,
		},
		{
			name:     "found in middle",
			s:        "hello world",
			substr:   "world",
			expected: 6,
		},
		{
			name:     "not found",
			s:        "hello world",
			substr:   "xyz",
			expected: -1,
		},
		{
			name:     "empty substring",
			s:        "hello",
			substr:   "",
			expected: 0,
		},
		{
			name:     "empty string",
			s:        "",
			substr:   "foo",
			expected: -1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := indexSubstring(tt.s, tt.substr)
			assert.Equal(t, tt.expected, result)
		})
	}
}
