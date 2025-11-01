package pcap

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPcapFilePermissions verifies that PCAP files are created with secure permissions (0600)
// This test addresses security concern from code review: Phase 1.4 - Fix PCAP File Permissions
func TestPcapFilePermissions(t *testing.T) {
	tempDir := filepath.Join(os.TempDir(), "lippycat-pcap-permissions-test")
	defer os.RemoveAll(tempDir)

	err := os.MkdirAll(tempDir, 0755)
	require.NoError(t, err)

	testFile := filepath.Join(tempDir, "test.pcap")

	// Create a new PCAP writer
	writer, err := NewWriter(testFile)
	require.NoError(t, err)
	require.NotNil(t, writer)

	// Stop the writer (closes the file)
	writer.Stop()

	// Check file permissions
	info, err := os.Stat(testFile)
	require.NoError(t, err)

	// Verify permissions are 0600 (owner read/write only)
	mode := info.Mode().Perm()
	assert.Equal(t, os.FileMode(0600), mode,
		"PCAP file should have 0600 permissions (owner read/write only), got %04o", mode)
}
