package filtering

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseFile(t *testing.T) {
	t.Run("valid file", func(t *testing.T) {
		tempDir := t.TempDir()
		filterFile := filepath.Join(tempDir, "filters.yaml")

		content := `filters:
  - id: filter-1
    type: sip_user
    pattern: alicent@example.com
    target_hunters:
      - hunter-1
      - hunter-2
    enabled: true
    description: "Alicent's calls"
  - id: filter-2
    type: ip_address
    pattern: 192.168.1.0/24
    enabled: true
`
		err := os.WriteFile(filterFile, []byte(content), 0600)
		require.NoError(t, err)

		filters, err := ParseFile(filterFile)
		require.NoError(t, err)
		assert.Len(t, filters, 2)

		filter1 := filters["filter-1"]
		require.NotNil(t, filter1)
		assert.Equal(t, "alicent@example.com", filter1.Pattern)
		assert.Equal(t, management.FilterType_FILTER_SIP_USER, filter1.Type)
		assert.Equal(t, []string{"hunter-1", "hunter-2"}, filter1.TargetHunters)
		assert.True(t, filter1.Enabled)

		filter2 := filters["filter-2"]
		require.NotNil(t, filter2)
		assert.Equal(t, "192.168.1.0/24", filter2.Pattern)
		assert.Equal(t, management.FilterType_FILTER_IP_ADDRESS, filter2.Type)
	})

	t.Run("non-existent file", func(t *testing.T) {
		filters, err := ParseFile("/nonexistent/path/filters.yaml")
		require.NoError(t, err)
		assert.Len(t, filters, 0)
	})

	t.Run("invalid YAML", func(t *testing.T) {
		tempDir := t.TempDir()
		filterFile := filepath.Join(tempDir, "filters.yaml")

		content := `this is not valid yaml: [[[`
		err := os.WriteFile(filterFile, []byte(content), 0600)
		require.NoError(t, err)

		_, err = ParseFile(filterFile)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to parse filter YAML")
	})

	t.Run("skips invalid filters", func(t *testing.T) {
		tempDir := t.TempDir()
		filterFile := filepath.Join(tempDir, "filters.yaml")

		content := `filters:
  - id: valid-filter
    type: sip_user
    pattern: user@example.com
    enabled: true
  - id: ""
    type: sip_user
    pattern: missing-id
    enabled: true
  - id: missing-pattern
    type: sip_user
    pattern: ""
    enabled: true
`
		err := os.WriteFile(filterFile, []byte(content), 0600)
		require.NoError(t, err)

		filters, err := ParseFile(filterFile)
		require.NoError(t, err)
		assert.Len(t, filters, 1)
		assert.NotNil(t, filters["valid-filter"])
	})
}

func TestParseFileWithErrors(t *testing.T) {
	t.Run("collects parse errors", func(t *testing.T) {
		tempDir := t.TempDir()
		filterFile := filepath.Join(tempDir, "filters.yaml")

		content := `filters:
  - id: valid-filter
    type: sip_user
    pattern: user@example.com
    enabled: true
  - id: invalid-type
    type: bad_type
    pattern: test
    enabled: true
  - id: ""
    type: sip_user
    pattern: no-id
    enabled: true
`
		err := os.WriteFile(filterFile, []byte(content), 0600)
		require.NoError(t, err)

		filters, parseErrors, err := ParseFileWithErrors(filterFile)
		require.NoError(t, err)
		assert.Len(t, filters, 1)
		assert.Len(t, parseErrors, 2)
	})

	t.Run("non-existent file", func(t *testing.T) {
		filters, parseErrors, err := ParseFileWithErrors("/nonexistent/path/filters.yaml")
		require.NoError(t, err)
		assert.Len(t, filters, 0)
		assert.Nil(t, parseErrors)
	})
}

func TestWriteFile(t *testing.T) {
	t.Run("write and read back", func(t *testing.T) {
		tempDir := t.TempDir()
		filterFile := filepath.Join(tempDir, "subdir", "filters.yaml")

		filters := map[string]*management.Filter{
			"filter-1": {
				Id:            "filter-1",
				Type:          management.FilterType_FILTER_SIP_USER,
				Pattern:       "alicent@example.com",
				TargetHunters: []string{"hunter-1", "hunter-2"},
				Enabled:       true,
				Description:   "Alicent's calls",
			},
			"filter-2": {
				Id:          "filter-2",
				Type:        management.FilterType_FILTER_IP_ADDRESS,
				Pattern:     "192.168.1.0/24",
				Enabled:     true,
				Description: "Local network",
			},
		}

		err := WriteFile(filterFile, filters)
		require.NoError(t, err)

		// Verify file exists
		_, err = os.Stat(filterFile)
		require.NoError(t, err)

		// Read back and verify
		loadedFilters, err := ParseFile(filterFile)
		require.NoError(t, err)
		assert.Len(t, loadedFilters, 2)

		assert.Equal(t, "alicent@example.com", loadedFilters["filter-1"].Pattern)
		assert.Equal(t, "192.168.1.0/24", loadedFilters["filter-2"].Pattern)
	})

	t.Run("creates directory", func(t *testing.T) {
		tempDir := t.TempDir()
		filterFile := filepath.Join(tempDir, "a", "b", "c", "filters.yaml")

		filters := map[string]*management.Filter{
			"test": {
				Id:      "test",
				Type:    management.FilterType_FILTER_BPF,
				Pattern: "port 5060",
				Enabled: true,
			},
		}

		err := WriteFile(filterFile, filters)
		require.NoError(t, err)

		_, err = os.Stat(filterFile)
		require.NoError(t, err)
	})

	t.Run("atomic write", func(t *testing.T) {
		tempDir := t.TempDir()
		filterFile := filepath.Join(tempDir, "filters.yaml")

		// Write initial file
		filters1 := map[string]*management.Filter{
			"filter-1": {
				Id:      "filter-1",
				Type:    management.FilterType_FILTER_SIP_USER,
				Pattern: "user1@example.com",
				Enabled: true,
			},
		}
		err := WriteFile(filterFile, filters1)
		require.NoError(t, err)

		// Overwrite with new content
		filters2 := map[string]*management.Filter{
			"filter-2": {
				Id:      "filter-2",
				Type:    management.FilterType_FILTER_IP_ADDRESS,
				Pattern: "10.0.0.0/8",
				Enabled: true,
			},
		}
		err = WriteFile(filterFile, filters2)
		require.NoError(t, err)

		// Verify only new content exists
		loaded, err := ParseFile(filterFile)
		require.NoError(t, err)
		assert.Len(t, loaded, 1)
		assert.Nil(t, loaded["filter-1"])
		assert.NotNil(t, loaded["filter-2"])

		// Verify no temp file left behind
		_, err = os.Stat(filterFile + ".tmp")
		assert.True(t, os.IsNotExist(err))
	})
}

func TestGetDefaultFilterFilePath(t *testing.T) {
	path := GetDefaultFilterFilePath()
	assert.NotEmpty(t, path)
	assert.Contains(t, path, "filters.yaml")
}
