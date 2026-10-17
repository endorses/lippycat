package filtering

import "github.com/endorses/lippycat/api/gen/management"

// ParseDistributionScope accepts the persisted/CLI spelling. An omitted scope
// preserves the distributed behavior of existing managed filters.
func ParseDistributionScope(value string) (management.FilterDistributionScope, error) {
	switch value {
	case "", "distributed":
		return management.FilterDistributionScope_FILTER_DISTRIBUTION_SCOPE_DISTRIBUTED, nil
	case "local_only":
		return management.FilterDistributionScope_FILTER_DISTRIBUTION_SCOPE_LOCAL_ONLY, nil
	default:
		return 0, &ValidationError{Field: "distribution_scope", Message: "must be distributed or local_only"}
	}
}

func DistributionScopeToString(scope management.FilterDistributionScope) string {
	switch scope {
	case management.FilterDistributionScope_FILTER_DISTRIBUTION_SCOPE_DISTRIBUTED:
		return "distributed"
	case management.FilterDistributionScope_FILTER_DISTRIBUTION_SCOPE_LOCAL_ONLY:
		return "local_only"
	default:
		return "unknown"
	}
}

// IsDistributedFilter is intentionally fail-closed for unrecognized scopes.
// Server-side queries and publication must use this before serializing policy
// for hunters, including clients predating the distribution_scope field.
func IsDistributedFilter(filter *management.Filter) bool {
	return filter != nil && filter.DistributionScope == management.FilterDistributionScope_FILTER_DISTRIBUTION_SCOPE_DISTRIBUTED
}
