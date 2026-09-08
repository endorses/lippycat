package filtering

import (
	"fmt"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/radius"
)

// IsRADIUSFilter identifies the additive exact-filter family.
func IsRADIUSFilterType(t management.FilterType) bool { return IsRADIUSFilter(t) }

func IsRADIUSFilter(t management.FilterType) bool {
	return t >= management.FilterType_FILTER_RADIUS_USERNAME && t <= management.FilterType_FILTER_RADIUS_COMPOUND
}

// CompileRADIUSFilter converts distributed criteria into the shared matcher.
// A compound filter is one conjunction, never a collection of independent IDs.
func CompileRADIUSFilter(f *management.Filter) (*radius.Predicate, *radius.Group, error) {
	if f == nil || !IsRADIUSFilter(f.Type) {
		return nil, nil, fmt.Errorf("not a RADIUS filter")
	}
	if f.Id == "" || len(f.Id) > 256 || f.Revision == 0 {
		return nil, nil, fmt.Errorf("RADIUS filter requires ID and positive revision")
	}
	if f.Type == management.FilterType_FILTER_RADIUS_COMPOUND {
		r := f.Radius
		if r == nil || r.Scope == nil || f.Pattern != "" || r.MacProfile != "" || r.TargetKind != "" {
			return nil, nil, fmt.Errorf("compound RADIUS filter requires structured criteria and scope only")
		}
		spec := radius.GroupSpec{ID: r.GroupId, TaskID: r.TaskId, TaskGeneration: r.TaskGeneration, Scope: radius.ScopeBinding{OperatorScope: r.Scope.OperatorScope, ProfileRevision: r.Scope.ProfileRevision, OriginNodeID: r.Scope.OriginNodeId, SourceID: r.Scope.SourceId}}
		for _, c := range r.Criteria {
			if c != nil && c.FilterRevision != f.Revision {
				return nil, nil, fmt.Errorf("RADIUS compound criterion revision must equal parent filter revision")
			}
			if c == nil {
				return nil, nil, fmt.Errorf("nil RADIUS criterion")
			}
			spec.Criteria = append(spec.Criteria, radius.PredicateSpec{Kind: c.Kind, Value: c.Value, MACProfile: c.MacProfile, TargetKind: c.TargetKind, FilterID: c.FilterId, FilterRevision: c.FilterRevision})
		}
		g, err := radius.CompileGroup(spec)
		return nil, g, err
	}
	spec := radius.PredicateSpec{Value: f.Pattern, FilterID: f.Id, FilterRevision: f.Revision}
	switch f.Type {
	case management.FilterType_FILTER_RADIUS_USERNAME:
		spec.Kind = radius.PredicateUserName
	case management.FilterType_FILTER_RADIUS_MAC:
		spec.Kind = radius.PredicateMAC
	case management.FilterType_FILTER_RADIUS_ATTRIBUTE:
		spec.Kind = radius.PredicateAttribute
	}
	if r := f.Radius; r != nil {
		if r.GroupId != "" || r.TaskId != "" || r.TaskGeneration != 0 || len(r.Criteria) > 0 {
			return nil, nil, fmt.Errorf("group ownership requires radius_compound")
		}
		spec.MACProfile = r.MacProfile
		spec.TargetKind = r.TargetKind
	}
	if f.Radius != nil && f.Radius.Scope != nil {
		scope := f.Radius.Scope
		g, err := radius.CompileGroup(radius.GroupSpec{ID: f.Id, Scope: radius.ScopeBinding{OperatorScope: scope.OperatorScope, ProfileRevision: scope.ProfileRevision, OriginNodeID: scope.OriginNodeId, SourceID: scope.SourceId}, Criteria: []radius.PredicateSpec{spec}})
		return nil, g, err
	}
	p, err := radius.CompilePredicate(spec)
	if err == nil && p.Spec().TargetKind == "line" {
		return nil, nil, fmt.Errorf("RADIUS line filter requires explicit operator scope and profile revision")
	}
	return p, nil, err
}
