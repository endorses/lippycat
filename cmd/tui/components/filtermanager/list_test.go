//go:build tui || all
// +build tui all

package filtermanager

import (
	"testing"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/stretchr/testify/assert"
)

func TestAbbreviateType(t *testing.T) {
	tests := []struct {
		name       string
		filterType management.FilterType
		expected   string
	}{
		{"SIP User", management.FilterType_FILTER_SIP_USER, "SIP User"},
		{"Phone", management.FilterType_FILTER_PHONE_NUMBER, "Phone"},
		{"IP Address", management.FilterType_FILTER_IP_ADDRESS, "IP Address"},
		{"Call-ID", management.FilterType_FILTER_CALL_ID, "Call-ID"},
		{"Codec", management.FilterType_FILTER_CODEC, "Codec"},
		{"BPF", management.FilterType_FILTER_BPF, "BPF"},
		{"Unknown", management.FilterType(999), "Unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := AbbreviateType(tt.filterType)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestTruncateString(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		max      int
		expected string
	}{
		{"Shorter than max", "hello", 10, "hello"},
		{"Exactly max", "hello", 5, "hello"},
		{"Longer than max", "hello world", 8, "hello..."},
		{"Max too small", "hello", 2, "he"},
		{"Empty string", "", 10, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := TruncateString(tt.input, tt.max)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestRenderSearchBar_NoSearch(t *testing.T) {
	result := RenderSearchBar(RenderSearchBarParams{
		SearchMode:      false,
		SearchValue:     "",
		FilterByType:    nil,
		FilterByEnabled: nil,
	})

	assert.Contains(t, result, "Search: (press / to search)")
	assert.Contains(t, result, "Type: All")
	assert.Contains(t, result, "Show: All")
}

func TestRenderSearchBar_WithSearch(t *testing.T) {
	result := RenderSearchBar(RenderSearchBarParams{
		SearchMode:      false,
		SearchValue:     "alice",
		FilterByType:    nil,
		FilterByEnabled: nil,
	})

	assert.Contains(t, result, "Search: alice")
}

func TestRenderSearchBar_WithTypeFilter(t *testing.T) {
	filterType := management.FilterType_FILTER_SIP_USER
	result := RenderSearchBar(RenderSearchBarParams{
		SearchMode:      false,
		SearchValue:     "",
		FilterByType:    &filterType,
		FilterByEnabled: nil,
	})

	assert.Contains(t, result, "Type: SIP User")
}

func TestRenderSearchBar_WithEnabledFilter(t *testing.T) {
	enabled := true
	result := RenderSearchBar(RenderSearchBarParams{
		SearchMode:      false,
		SearchValue:     "",
		FilterByType:    nil,
		FilterByEnabled: &enabled,
	})

	assert.Contains(t, result, "Show: ✓ Enabled")

	disabled := false
	result = RenderSearchBar(RenderSearchBarParams{
		SearchMode:      false,
		SearchValue:     "",
		FilterByType:    nil,
		FilterByEnabled: &disabled,
	})

	assert.Contains(t, result, "Show: ✗ Disabled")
}

func TestFilterItem_FilterValue(t *testing.T) {
	filter := &management.Filter{
		Pattern:       "alice@example.com",
		Description:   "Test user",
		Type:          management.FilterType_FILTER_SIP_USER,
		TargetHunters: []string{"hunter1", "hunter2"},
	}

	item := FilterItem{Filter: filter}
	filterValue := item.FilterValue()

	// Should be lowercase and contain all searchable fields
	assert.Contains(t, filterValue, "alice@example.com")
	assert.Contains(t, filterValue, "test user")
	assert.Contains(t, filterValue, "filter_sip_user")
	assert.Contains(t, filterValue, "hunter1")
	assert.Contains(t, filterValue, "hunter2")
}
