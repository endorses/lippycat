//go:build tui || all

package filtermanager

import (
	"testing"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/stretchr/testify/assert"
)

func TestValidateFilter_EmptyPattern(t *testing.T) {
	result := ValidateFilter(ValidateFilterParams{
		Pattern:     "",
		Description: "Test",
		Type:        management.FilterType_FILTER_SIP_USER,
	})

	assert.False(t, result.Valid)
	assert.Equal(t, "Pattern cannot be empty", result.ErrorMessage)
}

func TestValidateFilter_WhitespacePattern(t *testing.T) {
	result := ValidateFilter(ValidateFilterParams{
		Pattern:     "   ",
		Description: "Test",
		Type:        management.FilterType_FILTER_SIP_USER,
	})

	assert.False(t, result.Valid)
	assert.Equal(t, "Pattern cannot be empty", result.ErrorMessage)
}

func TestValidateFilter_ValidPattern(t *testing.T) {
	// Mock VoIP hunter to satisfy validation
	mockHunters := []HunterSelectorItem{
		{
			HunterID: "hunter-1",
			Hostname: "test-host",
			Capabilities: &management.HunterCapabilities{
				FilterTypes: []string{"bpf", "sip_user", "phone_number", "call_id", "codec"},
			},
		},
	}

	result := ValidateFilter(ValidateFilterParams{
		Pattern:          "alicent@example.com",
		Description:      "Test user",
		Type:             management.FilterType_FILTER_SIP_USER,
		AvailableHunters: mockHunters,
	})

	assert.True(t, result.Valid)
	assert.Empty(t, result.ErrorMessage)
}

func TestToggleFilterEnabled(t *testing.T) {
	filter := &management.Filter{
		Pattern: "alicent",
		Enabled: true,
	}

	result := ToggleFilterEnabled(ToggleFilterEnabledParams{
		Filter: filter,
	})

	assert.False(t, result.NewEnabled)
	assert.Contains(t, result.StatusMessage, "alicent")
	assert.Contains(t, result.StatusMessage, "disabled")
}

func TestToggleFilterEnabled_NilFilter(t *testing.T) {
	result := ToggleFilterEnabled(ToggleFilterEnabledParams{
		Filter: nil,
	})

	assert.False(t, result.NewEnabled)
	assert.Empty(t, result.StatusMessage)
}

func TestDeleteFilter(t *testing.T) {
	filters := []*management.Filter{
		{Id: "1", Pattern: "alicent"},
		{Id: "2", Pattern: "robb"},
		{Id: "3", Pattern: "charlie"},
	}

	result := DeleteFilter(DeleteFilterParams{
		Filter:     filters[1],
		AllFilters: filters,
	})

	assert.Len(t, result.UpdatedFilters, 2)
	assert.Equal(t, "alicent", result.UpdatedFilters[0].Pattern)
	assert.Equal(t, "charlie", result.UpdatedFilters[1].Pattern)
	assert.Contains(t, result.StatusMessage, "robb")
	assert.Contains(t, result.StatusMessage, "deleted")
}

func TestDeleteFilter_NilFilter(t *testing.T) {
	filters := []*management.Filter{
		{Id: "1", Pattern: "alicent"},
	}

	result := DeleteFilter(DeleteFilterParams{
		Filter:     nil,
		AllFilters: filters,
	})

	assert.Equal(t, filters, result.UpdatedFilters)
	assert.Empty(t, result.StatusMessage)
}

func TestCreateFilter(t *testing.T) {
	existingFilters := []*management.Filter{
		{Id: "1", Pattern: "alicent"},
	}

	result := CreateFilter(CreateFilterParams{
		Pattern:       "robb@example.com",
		Description:   "Test user",
		Type:          management.FilterType_FILTER_SIP_USER,
		Enabled:       true,
		TargetHunters: []string{"hunter1"},
		AllFilters:    existingFilters,
	})

	assert.NotNil(t, result.Filter)
	assert.Equal(t, "robb@example.com", result.Filter.Pattern)
	assert.Equal(t, "Test user", result.Filter.Description)
	assert.True(t, result.Filter.Enabled)
	assert.Equal(t, []string{"hunter1"}, result.Filter.TargetHunters)

	assert.Len(t, result.UpdatedFilters, 2)
	assert.Contains(t, result.StatusMessage, "Creating")
	assert.Contains(t, result.StatusMessage, "robb@example.com")
}

func TestUpdateFilter(t *testing.T) {
	filters := []*management.Filter{
		{Id: "1", Pattern: "alicent", Enabled: true},
		{Id: "2", Pattern: "robb", Enabled: false},
	}

	result := UpdateFilter(UpdateFilterParams{
		FilterID:      "1",
		Pattern:       "alicent-updated",
		Description:   "Updated description",
		Type:          management.FilterType_FILTER_PHONE_NUMBER,
		Enabled:       false,
		TargetHunters: []string{"hunter1", "hunter2"},
		AllFilters:    filters,
	})

	assert.True(t, result.Found)
	assert.NotNil(t, result.Filter)
	assert.Equal(t, "alicent-updated", result.Filter.Pattern)
	assert.Equal(t, "Updated description", result.Filter.Description)
	assert.Equal(t, management.FilterType_FILTER_PHONE_NUMBER, result.Filter.Type)
	assert.False(t, result.Filter.Enabled)
	assert.Equal(t, []string{"hunter1", "hunter2"}, result.Filter.TargetHunters)

	assert.Contains(t, result.StatusMessage, "Updating")
	assert.Contains(t, result.StatusMessage, "alicent-updated")
}

func TestUpdateFilter_NotFound(t *testing.T) {
	filters := []*management.Filter{
		{Id: "1", Pattern: "alicent"},
	}

	result := UpdateFilter(UpdateFilterParams{
		FilterID:   "999",
		Pattern:    "nonexistent",
		AllFilters: filters,
	})

	assert.False(t, result.Found)
	assert.Nil(t, result.Filter)
	assert.Contains(t, result.StatusMessage, "not found")
}

func TestFormatOperationResult_Success(t *testing.T) {
	tests := []struct {
		name      string
		operation string
		pattern   string
		hunters   uint32
		expected  string
	}{
		{
			name:      "Create operation",
			operation: "create",
			pattern:   "alicent",
			hunters:   2,
			expected:  "Filter 'alicent' created (2 hunter(s) updated)",
		},
		{
			name:      "Update operation",
			operation: "update",
			pattern:   "robb",
			hunters:   1,
			expected:  "Filter 'robb' updated (1 hunter(s) updated)",
		},
		{
			name:      "Toggle operation",
			operation: "toggle",
			pattern:   "charlie",
			hunters:   3,
			expected:  "Filter 'charlie' updated (3 hunter(s) updated)",
		},
		{
			name:      "Delete operation",
			operation: "delete",
			pattern:   "dave",
			hunters:   0,
			expected:  "Filter 'dave' deleted (0 hunter(s) updated)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := FormatOperationResult(FormatOperationResultParams{
				Success:        true,
				Operation:      tt.operation,
				FilterPattern:  tt.pattern,
				HuntersUpdated: tt.hunters,
			})

			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestFormatOperationResult_Failure(t *testing.T) {
	result := FormatOperationResult(FormatOperationResultParams{
		Success:       false,
		Operation:     "create",
		FilterPattern: "alicent",
		Error:         "connection timeout",
	})

	assert.Contains(t, result, "Failed to create filter")
	assert.Contains(t, result, "connection timeout")
}
