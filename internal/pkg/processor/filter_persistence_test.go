package processor

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFilterPersistence(t *testing.T) {
	// Create temp directory for test
	tempDir := t.TempDir()
	filterFile := filepath.Join(tempDir, "filters.yaml")

	// Test 1: Save filters to YAML
	t.Run("SaveFilters", func(t *testing.T) {
		p := &Processor{
			config: Config{FilterFile: filterFile},
			filters: map[string]*management.Filter{
				"filter-1": {
					Id:            "filter-1",
					Type:          management.FilterType_FILTER_SIP_USER,
					Pattern:       "alice@example.com",
					TargetHunters: []string{"hunter-1", "hunter-2"},
					Enabled:       true,
					Description:   "Alice's calls",
				},
				"filter-2": {
					Id:          "filter-2",
					Type:        management.FilterType_FILTER_IP_ADDRESS,
					Pattern:     "192.168.1.0/24",
					Enabled:     true,
					Description: "Local network",
				},
			},
		}

		err := p.saveFilters()
		require.NoError(t, err, "saveFilters should succeed")

		// Verify file was created
		_, err = os.Stat(filterFile)
		require.NoError(t, err, "filter file should exist")

		// Read and verify content
		data, err := os.ReadFile(filterFile)
		require.NoError(t, err, "should be able to read filter file")
		assert.Contains(t, string(data), "filter-1")
		assert.Contains(t, string(data), "alice@example.com")
		assert.Contains(t, string(data), "filter-2")
		assert.Contains(t, string(data), "192.168.1.0/24")
	})

	// Test 2: Load filters from YAML
	t.Run("LoadFilters", func(t *testing.T) {
		p := &Processor{
			config:  Config{FilterFile: filterFile},
			filters: make(map[string]*management.Filter),
		}

		err := p.loadFilters()
		require.NoError(t, err, "loadFilters should succeed")

		// Verify filters were loaded
		assert.Len(t, p.filters, 2, "should load 2 filters")

		filter1 := p.filters["filter-1"]
		require.NotNil(t, filter1, "filter-1 should exist")
		assert.Equal(t, "alice@example.com", filter1.Pattern)
		assert.Equal(t, management.FilterType_FILTER_SIP_USER, filter1.Type)
		assert.Equal(t, []string{"hunter-1", "hunter-2"}, filter1.TargetHunters)
		assert.True(t, filter1.Enabled)

		filter2 := p.filters["filter-2"]
		require.NotNil(t, filter2, "filter-2 should exist")
		assert.Equal(t, "192.168.1.0/24", filter2.Pattern)
		assert.Equal(t, management.FilterType_FILTER_IP_ADDRESS, filter2.Type)
	})

	// Test 3: Load from non-existent file (should not error)
	t.Run("LoadFromNonExistentFile", func(t *testing.T) {
		p := &Processor{
			config:  Config{FilterFile: filepath.Join(tempDir, "nonexistent.yaml")},
			filters: make(map[string]*management.Filter),
		}

		err := p.loadFilters()
		require.NoError(t, err, "loading from non-existent file should not error")
		assert.Len(t, p.filters, 0, "should have no filters")
	})

	// Test 4: UpdateFilter persists to disk
	t.Run("UpdateFilterPersistence", func(t *testing.T) {
		filterFile2 := filepath.Join(tempDir, "filters2.yaml")
		p := &Processor{
			config:         Config{FilterFile: filterFile2},
			filters:        make(map[string]*management.Filter),
			filterChannels: make(map[string]chan *management.FilterUpdate),
		}

		ctx := context.Background()
		newFilter := &management.Filter{
			Id:          "filter-3",
			Type:        management.FilterType_FILTER_CODEC,
			Pattern:     "G.711",
			Enabled:     true,
			Description: "Codec filter",
		}

		_, err := p.UpdateFilter(ctx, newFilter)
		require.NoError(t, err, "UpdateFilter should succeed")

		// Verify file was created and contains the filter
		data, err := os.ReadFile(filterFile2)
		require.NoError(t, err, "should be able to read filter file")
		assert.Contains(t, string(data), "filter-3")
		assert.Contains(t, string(data), "G.711")

		// Load in new processor and verify
		p2 := &Processor{
			config:  Config{FilterFile: filterFile2},
			filters: make(map[string]*management.Filter),
		}
		err = p2.loadFilters()
		require.NoError(t, err, "should load filters")
		assert.Len(t, p2.filters, 1, "should have 1 filter")
		assert.Equal(t, "G.711", p2.filters["filter-3"].Pattern)
	})

	// Test 5: DeleteFilter persists to disk
	t.Run("DeleteFilterPersistence", func(t *testing.T) {
		filterFile3 := filepath.Join(tempDir, "filters3.yaml")

		// Create processor with initial filters
		p := &Processor{
			config: Config{FilterFile: filterFile3},
			filters: map[string]*management.Filter{
				"filter-1": {
					Id:      "filter-1",
					Type:    management.FilterType_FILTER_SIP_USER,
					Pattern: "alice@example.com",
					Enabled: true,
				},
				"filter-2": {
					Id:      "filter-2",
					Type:    management.FilterType_FILTER_IP_ADDRESS,
					Pattern: "192.168.1.0/24",
					Enabled: true,
				},
			},
			filterChannels: make(map[string]chan *management.FilterUpdate),
		}

		// Save initial state
		err := p.saveFilters()
		require.NoError(t, err)

		// Delete a filter
		ctx := context.Background()
		_, err = p.DeleteFilter(ctx, &management.FilterDeleteRequest{FilterId: "filter-1"})
		require.NoError(t, err, "DeleteFilter should succeed")

		// Verify file was updated
		data, err := os.ReadFile(filterFile3)
		require.NoError(t, err, "should be able to read filter file")
		assert.NotContains(t, string(data), "filter-1", "deleted filter should not be in file")
		assert.Contains(t, string(data), "filter-2", "remaining filter should be in file")

		// Load in new processor and verify
		p2 := &Processor{
			config:  Config{FilterFile: filterFile3},
			filters: make(map[string]*management.Filter),
		}
		err = p2.loadFilters()
		require.NoError(t, err, "should load filters")
		assert.Len(t, p2.filters, 1, "should have 1 filter after deletion")
		assert.Nil(t, p2.filters["filter-1"], "deleted filter should not exist")
		assert.NotNil(t, p2.filters["filter-2"], "remaining filter should exist")
	})
}

func TestFilterTypeConversion(t *testing.T) {
	tests := []struct {
		name      string
		yamlType  string
		protoType management.FilterType
		expectErr bool
	}{
		{"SIPUser", "sip_user", management.FilterType_FILTER_SIP_USER, false},
		{"SIPUserUpper", "FILTER_SIP_USER", management.FilterType_FILTER_SIP_USER, false},
		{"PhoneNumber", "phone_number", management.FilterType_FILTER_PHONE_NUMBER, false},
		{"IPAddress", "ip_address", management.FilterType_FILTER_IP_ADDRESS, false},
		{"CallID", "call_id", management.FilterType_FILTER_CALL_ID, false},
		{"Codec", "codec", management.FilterType_FILTER_CODEC, false},
		{"BPF", "bpf", management.FilterType_FILTER_BPF, false},
		{"Invalid", "invalid_type", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parseFilterType(tt.yamlType)
			if tt.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.protoType, result)
			}
		})
	}
}

func TestYAMLToProtoConversion(t *testing.T) {
	t.Run("ValidFilter", func(t *testing.T) {
		yaml := &FilterYAML{
			ID:            "test-filter",
			Type:          "sip_user",
			Pattern:       "user@domain.com",
			TargetHunters: []string{"hunter-1"},
			Enabled:       true,
			Description:   "Test filter",
		}

		proto, err := yamlToProtoFilter(yaml)
		require.NoError(t, err)
		assert.Equal(t, "test-filter", proto.Id)
		assert.Equal(t, management.FilterType_FILTER_SIP_USER, proto.Type)
		assert.Equal(t, "user@domain.com", proto.Pattern)
		assert.Equal(t, []string{"hunter-1"}, proto.TargetHunters)
		assert.True(t, proto.Enabled)
		assert.Equal(t, "Test filter", proto.Description)
	})

	t.Run("MissingID", func(t *testing.T) {
		yaml := &FilterYAML{
			Type:    "sip_user",
			Pattern: "user@domain.com",
		}

		_, err := yamlToProtoFilter(yaml)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "ID is required")
	})

	t.Run("MissingPattern", func(t *testing.T) {
		yaml := &FilterYAML{
			ID:   "test-filter",
			Type: "sip_user",
		}

		_, err := yamlToProtoFilter(yaml)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "pattern is required")
	})
}

func TestProtoToYAMLConversion(t *testing.T) {
	proto := &management.Filter{
		Id:            "test-filter",
		Type:          management.FilterType_FILTER_IP_ADDRESS,
		Pattern:       "10.0.0.0/8",
		TargetHunters: []string{"hunter-1", "hunter-2"},
		Enabled:       false,
		Description:   "Private network",
	}

	yaml := protoToYAMLFilter(proto)
	assert.Equal(t, "test-filter", yaml.ID)
	assert.Equal(t, "ip_address", yaml.Type)
	assert.Equal(t, "10.0.0.0/8", yaml.Pattern)
	assert.Equal(t, []string{"hunter-1", "hunter-2"}, yaml.TargetHunters)
	assert.False(t, yaml.Enabled)
	assert.Equal(t, "Private network", yaml.Description)
}
