package filtering

import (
	"fmt"

	"github.com/endorses/lippycat/api/gen/management"
)

// ValidationError represents a filter validation error
type ValidationError struct {
	Field   string
	Message string
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("%s: %s", e.Field, e.Message)
}

// ValidateFilterYAML validates a FilterYAML structure
func ValidateFilterYAML(filter *FilterYAML) error {
	if filter.ID == "" {
		return &ValidationError{Field: "id", Message: "filter ID is required"}
	}
	if filter.Pattern == "" {
		return &ValidationError{Field: "pattern", Message: "filter pattern is required"}
	}
	if filter.Type == "" {
		return &ValidationError{Field: "type", Message: "filter type is required"}
	}
	if err := ValidateFilterType(filter.Type); err != nil {
		return err
	}
	return nil
}

// ValidateFilter validates a protobuf Filter structure
func ValidateFilter(filter *management.Filter) error {
	if filter.Id == "" {
		return &ValidationError{Field: "id", Message: "filter ID is required"}
	}
	if filter.Pattern == "" {
		return &ValidationError{Field: "pattern", Message: "filter pattern is required"}
	}
	// Protobuf enum is always valid by type system, but check for unspecified
	// Note: FILTER_SIP_USER is 0, which is also the default, so we can't detect "unset"
	// This is acceptable as SIP_USER is a valid default
	return nil
}

// ValidateFilterType validates a filter type string
func ValidateFilterType(typeStr string) error {
	if !ValidFilterTypes[typeStr] {
		return &ValidationError{
			Field:   "type",
			Message: fmt.Sprintf("unknown filter type: %s", typeStr),
		}
	}
	return nil
}
