//go:build tui || all

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

// allFilterTypes is the ordered list of all filter types for cycling
var allFilterTypes = []management.FilterType{
	// VoIP filters
	management.FilterType_FILTER_SIP_USER,
	management.FilterType_FILTER_PHONE_NUMBER,
	management.FilterType_FILTER_IP_ADDRESS,
	management.FilterType_FILTER_CALL_ID,
	management.FilterType_FILTER_CODEC,
	management.FilterType_FILTER_BPF,
	management.FilterType_FILTER_SIP_URI,
	// DNS filters
	management.FilterType_FILTER_DNS_DOMAIN,
	// Email filters
	management.FilterType_FILTER_EMAIL_ADDRESS,
	management.FilterType_FILTER_EMAIL_SUBJECT,
	// TLS filters
	management.FilterType_FILTER_TLS_SNI,
	management.FilterType_FILTER_TLS_JA3,
	management.FilterType_FILTER_TLS_JA3S,
	management.FilterType_FILTER_TLS_JA4,
	// HTTP filters
	management.FilterType_FILTER_HTTP_HOST,
	management.FilterType_FILTER_HTTP_URL,
}

// CycleTypeFilter cycles through filter type options
func CycleTypeFilter(params CycleTypeFilterParams) CycleTypeFilterResult {
	// Find current index in the list
	currentIdx := -1
	if params.CurrentType != nil {
		for i, t := range allFilterTypes {
			if t == *params.CurrentType {
				currentIdx = i
				break
			}
		}
	}

	if params.Forward {
		// Forward: All → first type → ... → last type → All
		if currentIdx == -1 {
			// Currently "All", go to first type
			t := allFilterTypes[0]
			return CycleTypeFilterResult{NewType: &t}
		}
		if currentIdx >= len(allFilterTypes)-1 {
			// At last type, go to "All"
			return CycleTypeFilterResult{NewType: nil}
		}
		// Go to next type
		t := allFilterTypes[currentIdx+1]
		return CycleTypeFilterResult{NewType: &t}
	} else {
		// Backward: All → last type → ... → first type → All
		if currentIdx == -1 {
			// Currently "All", go to last type
			t := allFilterTypes[len(allFilterTypes)-1]
			return CycleTypeFilterResult{NewType: &t}
		}
		if currentIdx <= 0 {
			// At first type, go to "All"
			return CycleTypeFilterResult{NewType: nil}
		}
		// Go to previous type
		t := allFilterTypes[currentIdx-1]
		return CycleTypeFilterResult{NewType: &t}
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
