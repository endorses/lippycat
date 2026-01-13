//go:build tui || all

package filtermanager

import (
	"testing"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/stretchr/testify/assert"
)

func TestApplyFilters_NoFilters(t *testing.T) {
	filters := []*management.Filter{
		{Pattern: "alicent", Type: management.FilterType_FILTER_SIP_USER, Enabled: true},
		{Pattern: "robb", Type: management.FilterType_FILTER_SIP_USER, Enabled: false},
	}

	result := ApplyFilters(StateParams{
		AllFilters:      filters,
		SearchQuery:     "",
		FilterByType:    nil,
		FilterByEnabled: nil,
	})

	assert.Len(t, result.FilteredFilters, 2)
	assert.Equal(t, "2 filters", result.StatusMessage)
}

func TestApplyFilters_SearchQuery(t *testing.T) {
	filters := []*management.Filter{
		{Pattern: "alicent@example.com", Type: management.FilterType_FILTER_SIP_USER, Enabled: true},
		{Pattern: "robb@example.com", Type: management.FilterType_FILTER_SIP_USER, Enabled: true},
		{Pattern: "192.168.1.1", Type: management.FilterType_FILTER_IP_ADDRESS, Enabled: true},
	}

	result := ApplyFilters(StateParams{
		AllFilters:      filters,
		SearchQuery:     "alicent",
		FilterByType:    nil,
		FilterByEnabled: nil,
	})

	assert.Len(t, result.FilteredFilters, 1)
	assert.Equal(t, "alicent@example.com", result.FilteredFilters[0].Pattern)
	assert.Equal(t, "Showing 1 of 3 filters", result.StatusMessage)
}

func TestApplyFilters_TypeFilter(t *testing.T) {
	filters := []*management.Filter{
		{Pattern: "alicent", Type: management.FilterType_FILTER_SIP_USER, Enabled: true},
		{Pattern: "192.168.1.1", Type: management.FilterType_FILTER_IP_ADDRESS, Enabled: true},
		{Pattern: "robb", Type: management.FilterType_FILTER_SIP_USER, Enabled: true},
	}

	filterType := management.FilterType_FILTER_SIP_USER
	result := ApplyFilters(StateParams{
		AllFilters:      filters,
		SearchQuery:     "",
		FilterByType:    &filterType,
		FilterByEnabled: nil,
	})

	assert.Len(t, result.FilteredFilters, 2)
	assert.Equal(t, "alicent", result.FilteredFilters[0].Pattern)
	assert.Equal(t, "robb", result.FilteredFilters[1].Pattern)
}

func TestApplyFilters_EnabledFilter(t *testing.T) {
	filters := []*management.Filter{
		{Pattern: "alicent", Type: management.FilterType_FILTER_SIP_USER, Enabled: true},
		{Pattern: "robb", Type: management.FilterType_FILTER_SIP_USER, Enabled: false},
		{Pattern: "charlie", Type: management.FilterType_FILTER_SIP_USER, Enabled: true},
	}

	enabled := true
	result := ApplyFilters(StateParams{
		AllFilters:      filters,
		SearchQuery:     "",
		FilterByType:    nil,
		FilterByEnabled: &enabled,
	})

	assert.Len(t, result.FilteredFilters, 2)
	assert.Equal(t, "alicent", result.FilteredFilters[0].Pattern)
	assert.Equal(t, "charlie", result.FilteredFilters[1].Pattern)
}

func TestApplyFilters_CombinedFilters(t *testing.T) {
	filters := []*management.Filter{
		{Pattern: "alicent@example.com", Type: management.FilterType_FILTER_SIP_USER, Enabled: true},
		{Pattern: "robb@example.com", Type: management.FilterType_FILTER_SIP_USER, Enabled: false},
		{Pattern: "charlie@example.com", Type: management.FilterType_FILTER_SIP_USER, Enabled: true},
		{Pattern: "192.168.1.1", Type: management.FilterType_FILTER_IP_ADDRESS, Enabled: true},
	}

	filterType := management.FilterType_FILTER_SIP_USER
	enabled := true
	result := ApplyFilters(StateParams{
		AllFilters:      filters,
		SearchQuery:     "example",
		FilterByType:    &filterType,
		FilterByEnabled: &enabled,
	})

	assert.Len(t, result.FilteredFilters, 2)
	assert.Equal(t, "alicent@example.com", result.FilteredFilters[0].Pattern)
	assert.Equal(t, "charlie@example.com", result.FilteredFilters[1].Pattern)
}

func TestCycleTypeFilter_Forward(t *testing.T) {
	// All → SIP User (first in the list)
	result := CycleTypeFilter(CycleTypeFilterParams{
		CurrentType: nil,
		Forward:     true,
	})
	assert.NotNil(t, result.NewType)
	assert.Equal(t, management.FilterType_FILTER_SIP_USER, *result.NewType)

	// SIP User → Phone
	result = CycleTypeFilter(CycleTypeFilterParams{
		CurrentType: result.NewType,
		Forward:     true,
	})
	assert.NotNil(t, result.NewType)
	assert.Equal(t, management.FilterType_FILTER_PHONE_NUMBER, *result.NewType)

	// BPF → SIP_URI (next in the list, not wrapping to All)
	bpf := management.FilterType_FILTER_BPF
	result = CycleTypeFilter(CycleTypeFilterParams{
		CurrentType: &bpf,
		Forward:     true,
	})
	assert.NotNil(t, result.NewType)
	assert.Equal(t, management.FilterType_FILTER_SIP_URI, *result.NewType)

	// HTTP_URL → All (last in list wraps to All)
	httpUrl := management.FilterType_FILTER_HTTP_URL
	result = CycleTypeFilter(CycleTypeFilterParams{
		CurrentType: &httpUrl,
		Forward:     true,
	})
	assert.Nil(t, result.NewType)
}

func TestCycleTypeFilter_Backward(t *testing.T) {
	// All → HTTP_URL (last in the list)
	result := CycleTypeFilter(CycleTypeFilterParams{
		CurrentType: nil,
		Forward:     false,
	})
	assert.NotNil(t, result.NewType)
	assert.Equal(t, management.FilterType_FILTER_HTTP_URL, *result.NewType)

	// HTTP_URL → HTTP_HOST (previous in list)
	result = CycleTypeFilter(CycleTypeFilterParams{
		CurrentType: result.NewType,
		Forward:     false,
	})
	assert.NotNil(t, result.NewType)
	assert.Equal(t, management.FilterType_FILTER_HTTP_HOST, *result.NewType)

	// SIP User → All (first in list wraps to All)
	sipUser := management.FilterType_FILTER_SIP_USER
	result = CycleTypeFilter(CycleTypeFilterParams{
		CurrentType: &sipUser,
		Forward:     false,
	})
	assert.Nil(t, result.NewType)
}

func TestCycleEnabledFilter_Forward(t *testing.T) {
	// All → Enabled
	result := CycleEnabledFilter(CycleEnabledFilterParams{
		CurrentEnabled: nil,
		Forward:        true,
	})
	assert.NotNil(t, result.NewEnabled)
	assert.True(t, *result.NewEnabled)

	// Enabled → Disabled
	result = CycleEnabledFilter(CycleEnabledFilterParams{
		CurrentEnabled: result.NewEnabled,
		Forward:        true,
	})
	assert.NotNil(t, result.NewEnabled)
	assert.False(t, *result.NewEnabled)

	// Disabled → All
	result = CycleEnabledFilter(CycleEnabledFilterParams{
		CurrentEnabled: result.NewEnabled,
		Forward:        true,
	})
	assert.Nil(t, result.NewEnabled)
}

func TestCycleEnabledFilter_Backward(t *testing.T) {
	// All → Disabled
	result := CycleEnabledFilter(CycleEnabledFilterParams{
		CurrentEnabled: nil,
		Forward:        false,
	})
	assert.NotNil(t, result.NewEnabled)
	assert.False(t, *result.NewEnabled)

	// Disabled → Enabled
	result = CycleEnabledFilter(CycleEnabledFilterParams{
		CurrentEnabled: result.NewEnabled,
		Forward:        false,
	})
	assert.NotNil(t, result.NewEnabled)
	assert.True(t, *result.NewEnabled)

	// Enabled → All
	result = CycleEnabledFilter(CycleEnabledFilterParams{
		CurrentEnabled: result.NewEnabled,
		Forward:        false,
	})
	assert.Nil(t, result.NewEnabled)
}

func TestTruncatePattern(t *testing.T) {
	tests := []struct {
		name     string
		pattern  string
		max      int
		expected string
	}{
		{"Shorter than max", "alicent", 10, "alicent"},
		{"Exactly max", "alicent", 7, "alicent"},
		{"Longer than max", "alicent@example.com", 10, "alicent..."},
		{"Max too small for ellipsis", "alicent", 2, "al"},
		{"Empty string", "", 10, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := TruncatePattern(tt.pattern, tt.max)
			assert.Equal(t, tt.expected, result)
		})
	}
}
