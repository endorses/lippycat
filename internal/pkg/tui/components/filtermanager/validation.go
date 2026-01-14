//go:build tui || all

package filtermanager

import (
	"fmt"
	"strings"

	"github.com/endorses/lippycat/api/gen/management"
)

// ValidateFilterParams holds input parameters for filter validation
type ValidateFilterParams struct {
	Pattern          string
	Description      string
	Type             management.FilterType
	AvailableHunters []HunterSelectorItem
}

// ValidateFilterResult holds the result of filter validation
type ValidateFilterResult struct {
	Valid        bool
	ErrorMessage string
	Warning      string // Non-fatal warning message
}

// ValidateFilter validates a filter before saving
func ValidateFilter(params ValidateFilterParams) ValidateFilterResult {
	// Validate pattern is not empty
	pattern := strings.TrimSpace(params.Pattern)
	if pattern == "" {
		return ValidateFilterResult{
			Valid:        false,
			ErrorMessage: "Pattern cannot be empty",
		}
	}

	// Check protocol-specific filter types against available hunters
	requiredMode := GetRequiredProtocolMode(params.Type)

	switch requiredMode {
	case "voip":
		if !HasVoIPHunters(params.AvailableHunters) {
			return ValidateFilterResult{
				Valid:        false,
				ErrorMessage: "No VoIP-capable hunters available. Start a VoIP hunter with 'lc hunt voip' or 'lc tap voip' to use this filter type.",
			}
		}
	case "dns":
		if !HasDNSHunters(params.AvailableHunters) {
			return ValidateFilterResult{
				Valid:        false,
				ErrorMessage: "No DNS-capable hunters available. Start a DNS hunter with 'lc hunt dns' or 'lc tap dns' to use this filter type.",
			}
		}
	case "email":
		if !HasEmailHunters(params.AvailableHunters) {
			return ValidateFilterResult{
				Valid:        false,
				ErrorMessage: "No Email-capable hunters available. Start an Email hunter with 'lc hunt email' or 'lc tap email' to use this filter type.",
			}
		}
	case "http":
		if !HasHTTPHunters(params.AvailableHunters) {
			return ValidateFilterResult{
				Valid:        false,
				ErrorMessage: "No HTTP-capable hunters available. Start an HTTP hunter with 'lc hunt http' or 'lc tap http' to use this filter type.",
			}
		}
	case "tls":
		if !HasTLSHunters(params.AvailableHunters) {
			return ValidateFilterResult{
				Valid:        false,
				ErrorMessage: "No TLS-capable hunters available. Start a TLS hunter with 'lc hunt tls' or 'lc tap tls' to use this filter type.",
			}
		}
	}

	// Additional validation could be added here based on filter type
	// For example, validate IP addresses, phone numbers, etc.

	return ValidateFilterResult{
		Valid:        true,
		ErrorMessage: "",
	}
}

// ToggleFilterEnabledParams holds input parameters for toggling filter enabled state
type ToggleFilterEnabledParams struct {
	Filter *management.Filter
}

// ToggleFilterEnabledResult holds the result of toggling filter enabled state
type ToggleFilterEnabledResult struct {
	StatusMessage string
	NewEnabled    bool
}

// ToggleFilterEnabled toggles the enabled state of a filter
func ToggleFilterEnabled(params ToggleFilterEnabledParams) ToggleFilterEnabledResult {
	if params.Filter == nil {
		return ToggleFilterEnabledResult{}
	}

	// Toggle the enabled state
	newEnabled := !params.Filter.Enabled

	// Build status message
	status := "disabled"
	if newEnabled {
		status = "enabled"
	}
	statusMsg := fmt.Sprintf("Filter '%s' %s", TruncatePattern(params.Filter.Pattern, 30), status)

	return ToggleFilterEnabledResult{
		StatusMessage: statusMsg,
		NewEnabled:    newEnabled,
	}
}

// DeleteFilterParams holds input parameters for deleting a filter
type DeleteFilterParams struct {
	Filter     *management.Filter
	AllFilters []*management.Filter
}

// DeleteFilterResult holds the result of deleting a filter
type DeleteFilterResult struct {
	UpdatedFilters []*management.Filter
	StatusMessage  string
}

// DeleteFilter removes a filter from the list
func DeleteFilter(params DeleteFilterParams) DeleteFilterResult {
	if params.Filter == nil {
		return DeleteFilterResult{
			UpdatedFilters: params.AllFilters,
			StatusMessage:  "",
		}
	}

	// Find and remove the filter
	filterID := params.Filter.Id
	patternForMsg := params.Filter.Pattern
	updatedFilters := make([]*management.Filter, 0, len(params.AllFilters))

	for _, filter := range params.AllFilters {
		if filter.Id != filterID {
			updatedFilters = append(updatedFilters, filter)
		}
	}

	statusMsg := fmt.Sprintf("Filter '%s' deleted", TruncatePattern(patternForMsg, 30))

	return DeleteFilterResult{
		UpdatedFilters: updatedFilters,
		StatusMessage:  statusMsg,
	}
}

// CreateFilterParams holds input parameters for creating a filter
type CreateFilterParams struct {
	Pattern       string
	Description   string
	Type          management.FilterType
	Enabled       bool
	TargetHunters []string
	AllFilters    []*management.Filter
}

// CreateFilterResult holds the result of creating a filter
type CreateFilterResult struct {
	Filter         *management.Filter
	UpdatedFilters []*management.Filter
	StatusMessage  string
}

// CreateFilter creates a new filter
func CreateFilter(params CreateFilterParams) CreateFilterResult {
	// Create new filter
	filter := &management.Filter{
		Id:            "", // Server will assign ID
		Pattern:       params.Pattern,
		Description:   params.Description,
		Type:          params.Type,
		Enabled:       params.Enabled,
		TargetHunters: params.TargetHunters,
	}

	// Add to local state with temporary ID
	tempFilter := &management.Filter{
		Id:            fmt.Sprintf("filter-%d", len(params.AllFilters)+1),
		Pattern:       filter.Pattern,
		Description:   filter.Description,
		Type:          filter.Type,
		Enabled:       filter.Enabled,
		TargetHunters: append([]string{}, filter.TargetHunters...),
	}

	updatedFilters := append(params.AllFilters, tempFilter)
	statusMsg := fmt.Sprintf("Creating filter '%s'...", TruncatePattern(params.Pattern, 30))

	return CreateFilterResult{
		Filter:         filter,
		UpdatedFilters: updatedFilters,
		StatusMessage:  statusMsg,
	}
}

// UpdateFilterParams holds input parameters for updating a filter
type UpdateFilterParams struct {
	FilterID      string
	Pattern       string
	Description   string
	Type          management.FilterType
	Enabled       bool
	TargetHunters []string
	AllFilters    []*management.Filter
}

// UpdateFilterResult holds the result of updating a filter
type UpdateFilterResult struct {
	Filter         *management.Filter
	UpdatedFilters []*management.Filter
	StatusMessage  string
	Found          bool
}

// UpdateFilter updates an existing filter
func UpdateFilter(params UpdateFilterParams) UpdateFilterResult {
	var updatedFilter *management.Filter

	// Copy all filters and update the matching one
	updatedFilters := make([]*management.Filter, len(params.AllFilters))
	for i, f := range params.AllFilters {
		if f.Id == params.FilterID {
			// Update this filter
			f.Pattern = params.Pattern
			f.Description = params.Description
			f.Type = params.Type
			f.Enabled = params.Enabled
			f.TargetHunters = params.TargetHunters
			updatedFilter = f
		}
		updatedFilters[i] = params.AllFilters[i]
	}

	if updatedFilter == nil {
		return UpdateFilterResult{
			Filter:         nil,
			UpdatedFilters: params.AllFilters,
			StatusMessage:  "Error: filter not found",
			Found:          false,
		}
	}

	statusMsg := fmt.Sprintf("Updating filter '%s'...", TruncatePattern(params.Pattern, 30))

	return UpdateFilterResult{
		Filter:         updatedFilter,
		UpdatedFilters: updatedFilters,
		StatusMessage:  statusMsg,
		Found:          true,
	}
}

// FormatOperationResultParams holds input parameters for formatting operation results
type FormatOperationResultParams struct {
	Success        bool
	Operation      string
	FilterPattern  string
	Error          string
	HuntersUpdated uint32
}

// FormatOperationResult formats the result of a filter operation
func FormatOperationResult(params FormatOperationResultParams) string {
	if params.Success {
		var statusMsg string
		switch params.Operation {
		case "create":
			statusMsg = fmt.Sprintf("Filter '%s' created (%d hunter(s) updated)", params.FilterPattern, params.HuntersUpdated)
		case "update", "toggle":
			statusMsg = fmt.Sprintf("Filter '%s' updated (%d hunter(s) updated)", params.FilterPattern, params.HuntersUpdated)
		case "delete":
			statusMsg = fmt.Sprintf("Filter '%s' deleted (%d hunter(s) updated)", params.FilterPattern, params.HuntersUpdated)
		default:
			statusMsg = fmt.Sprintf("Filter operation completed (%d hunter(s) updated)", params.HuntersUpdated)
		}
		return statusMsg
	}

	// Operation failed - show error
	return fmt.Sprintf("Failed to %s filter: %s", params.Operation, params.Error)
}
