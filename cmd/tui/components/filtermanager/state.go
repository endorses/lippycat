//go:build tui || all
// +build tui all

package filtermanager

import (
	"fmt"
	"strings"

	"github.com/endorses/lippycat/api/gen/management"
)

// StateParams holds input parameters for filter state operations
type StateParams struct {
	AllFilters      []*management.Filter
	SearchQuery     string
	FilterByType    *management.FilterType
	FilterByEnabled *bool
}

// StateResult holds the result of filter state operations
type StateResult struct {
	FilteredFilters []*management.Filter
	StatusMessage   string
}

// ApplyFilters applies search and filter criteria to the filter list
// This is a pure function with no side effects
func ApplyFilters(params StateParams) StateResult {
	filteredFilters := make([]*management.Filter, 0)
	searchLower := strings.ToLower(params.SearchQuery)

	for _, filter := range params.AllFilters {
		// Apply type filter
		if params.FilterByType != nil && filter.Type != *params.FilterByType {
			continue
		}

		// Apply enabled filter
		if params.FilterByEnabled != nil && filter.Enabled != *params.FilterByEnabled {
			continue
		}

		// Apply search filter
		if searchLower != "" {
			pattern := strings.ToLower(filter.Pattern)
			desc := strings.ToLower(filter.Description)
			typeName := strings.ToLower(filter.Type.String())
			targets := strings.ToLower(strings.Join(filter.TargetHunters, " "))

			if !strings.Contains(pattern, searchLower) &&
				!strings.Contains(desc, searchLower) &&
				!strings.Contains(typeName, searchLower) &&
				!strings.Contains(targets, searchLower) {
				continue
			}
		}

		filteredFilters = append(filteredFilters, filter)
	}

	// Build status message
	totalFilters := len(params.AllFilters)
	filteredCount := len(filteredFilters)

	var statusMsg string
	if totalFilters == filteredCount {
		statusMsg = fmt.Sprintf("%d filters", totalFilters)
	} else {
		statusMsg = fmt.Sprintf("Showing %d of %d filters", filteredCount, totalFilters)
	}

	return StateResult{
		FilteredFilters: filteredFilters,
		StatusMessage:   statusMsg,
	}
}

// CycleTypeFilterParams holds input parameters for cycling filter type
type CycleTypeFilterParams struct {
	CurrentType *management.FilterType
	Forward     bool
}

// CycleTypeFilterResult holds the result of cycling filter type
type CycleTypeFilterResult struct {
	NewType *management.FilterType
}

// CycleTypeFilter cycles through filter type options
func CycleTypeFilter(params CycleTypeFilterParams) CycleTypeFilterResult {
	if params.Forward {
		// Forward: All → SIP User → Phone → IP → Call-ID → Codec → BPF → All
		if params.CurrentType == nil {
			t := management.FilterType_FILTER_SIP_USER
			return CycleTypeFilterResult{NewType: &t}
		}

		switch *params.CurrentType {
		case management.FilterType_FILTER_SIP_USER:
			t := management.FilterType_FILTER_PHONE_NUMBER
			return CycleTypeFilterResult{NewType: &t}
		case management.FilterType_FILTER_PHONE_NUMBER:
			t := management.FilterType_FILTER_IP_ADDRESS
			return CycleTypeFilterResult{NewType: &t}
		case management.FilterType_FILTER_IP_ADDRESS:
			t := management.FilterType_FILTER_CALL_ID
			return CycleTypeFilterResult{NewType: &t}
		case management.FilterType_FILTER_CALL_ID:
			t := management.FilterType_FILTER_CODEC
			return CycleTypeFilterResult{NewType: &t}
		case management.FilterType_FILTER_CODEC:
			t := management.FilterType_FILTER_BPF
			return CycleTypeFilterResult{NewType: &t}
		case management.FilterType_FILTER_BPF:
			return CycleTypeFilterResult{NewType: nil}
		default:
			return CycleTypeFilterResult{NewType: nil}
		}
	} else {
		// Backward: All → BPF → Codec → Call-ID → IP → Phone → SIP User → All
		if params.CurrentType == nil {
			t := management.FilterType_FILTER_BPF
			return CycleTypeFilterResult{NewType: &t}
		}

		switch *params.CurrentType {
		case management.FilterType_FILTER_BPF:
			t := management.FilterType_FILTER_CODEC
			return CycleTypeFilterResult{NewType: &t}
		case management.FilterType_FILTER_CODEC:
			t := management.FilterType_FILTER_CALL_ID
			return CycleTypeFilterResult{NewType: &t}
		case management.FilterType_FILTER_CALL_ID:
			t := management.FilterType_FILTER_IP_ADDRESS
			return CycleTypeFilterResult{NewType: &t}
		case management.FilterType_FILTER_IP_ADDRESS:
			t := management.FilterType_FILTER_PHONE_NUMBER
			return CycleTypeFilterResult{NewType: &t}
		case management.FilterType_FILTER_PHONE_NUMBER:
			t := management.FilterType_FILTER_SIP_USER
			return CycleTypeFilterResult{NewType: &t}
		case management.FilterType_FILTER_SIP_USER:
			return CycleTypeFilterResult{NewType: nil}
		default:
			return CycleTypeFilterResult{NewType: nil}
		}
	}
}

// CycleEnabledFilterParams holds input parameters for cycling enabled filter
type CycleEnabledFilterParams struct {
	CurrentEnabled *bool
	Forward        bool
}

// CycleEnabledFilterResult holds the result of cycling enabled filter
type CycleEnabledFilterResult struct {
	NewEnabled *bool
}

// CycleEnabledFilter cycles through enabled filter options
func CycleEnabledFilter(params CycleEnabledFilterParams) CycleEnabledFilterResult {
	if params.Forward {
		// Forward: All → Enabled Only → Disabled Only → All
		if params.CurrentEnabled == nil {
			t := true
			return CycleEnabledFilterResult{NewEnabled: &t}
		} else if *params.CurrentEnabled {
			f := false
			return CycleEnabledFilterResult{NewEnabled: &f}
		} else {
			return CycleEnabledFilterResult{NewEnabled: nil}
		}
	} else {
		// Backward: All → Disabled Only → Enabled Only → All
		if params.CurrentEnabled == nil {
			f := false
			return CycleEnabledFilterResult{NewEnabled: &f}
		} else if !*params.CurrentEnabled {
			t := true
			return CycleEnabledFilterResult{NewEnabled: &t}
		} else {
			return CycleEnabledFilterResult{NewEnabled: nil}
		}
	}
}

// TruncatePattern truncates a pattern for display
func TruncatePattern(pattern string, max int) string {
	if len(pattern) <= max {
		return pattern
	}
	if max <= 3 {
		return pattern[:max]
	}
	return pattern[:max-3] + "..."
}
