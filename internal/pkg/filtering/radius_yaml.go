package filtering

import (
	"fmt"
	"github.com/endorses/lippycat/api/gen/management"
	"gopkg.in/yaml.v3"
)

func radiusYAMLToProto(r *RadiusFilterYAML) *management.RadiusFilterCriteria {
	if r == nil {
		return nil
	}
	out := &management.RadiusFilterCriteria{MacProfile: r.MacProfile, TargetKind: r.TargetKind, GroupId: r.GroupID, TaskId: r.TaskID, TaskGeneration: r.TaskGeneration}
	if s := r.Scope; s != nil {
		out.Scope = &management.RadiusScopeBinding{OperatorScope: s.OperatorScope, ProfileRevision: s.ProfileRevision, OriginNodeId: s.OriginNodeID, SourceId: s.SourceID}
	}
	for _, c := range r.Criteria {
		if c == nil {
			out.Criteria = append(out.Criteria, nil)
			continue
		}
		out.Criteria = append(out.Criteria, &management.RadiusCriterion{FilterId: c.FilterID, FilterRevision: c.FilterRevision, Kind: c.Kind, Value: c.Value, MacProfile: c.MacProfile, TargetKind: c.TargetKind})
	}
	return out
}
func radiusProtoToYAML(r *management.RadiusFilterCriteria) *RadiusFilterYAML {
	if r == nil {
		return nil
	}
	out := &RadiusFilterYAML{MacProfile: r.MacProfile, TargetKind: r.TargetKind, GroupID: r.GroupId, TaskID: r.TaskId, TaskGeneration: r.TaskGeneration}
	if s := r.Scope; s != nil {
		out.Scope = &RadiusScopeYAML{OperatorScope: s.OperatorScope, ProfileRevision: s.ProfileRevision, OriginNodeID: s.OriginNodeId, SourceID: s.SourceId}
	}
	for _, c := range r.Criteria {
		if c == nil {
			out.Criteria = append(out.Criteria, nil)
			continue
		}
		out.Criteria = append(out.Criteria, &RadiusCriterionYAML{FilterID: c.FilterId, FilterRevision: c.FilterRevision, Kind: c.Kind, Value: c.Value, MacProfile: c.MacProfile, TargetKind: c.TargetKind})
	}
	return out
}

// Reject misspelled scope or criterion keys instead of broadening selection.
func radiusKnownKeys(n *yaml.Node, keys ...string) error {
	if n.Kind != yaml.MappingNode {
		return fmt.Errorf("RADIUS criteria require a mapping")
	}
	allowed := make(map[string]bool, len(keys))
	for _, key := range keys {
		allowed[key] = true
	}
	for i := 0; i < len(n.Content); i += 2 {
		if !allowed[n.Content[i].Value] {
			return fmt.Errorf("unknown RADIUS field %q", n.Content[i].Value)
		}
	}
	return nil
}
func (r *RadiusFilterYAML) UnmarshalYAML(n *yaml.Node) error {
	if err := radiusKnownKeys(n, "mac_profile", "target_kind", "group_id", "task_id", "task_generation", "scope", "criteria"); err != nil {
		return err
	}
	type plain RadiusFilterYAML
	return n.Decode((*plain)(r))
}
func (r *RadiusScopeYAML) UnmarshalYAML(n *yaml.Node) error {
	if err := radiusKnownKeys(n, "operator_scope", "profile_revision", "origin_node_id", "source_id"); err != nil {
		return err
	}
	type plain RadiusScopeYAML
	return n.Decode((*plain)(r))
}
func (r *RadiusCriterionYAML) UnmarshalYAML(n *yaml.Node) error {
	if err := radiusKnownKeys(n, "filter_id", "filter_revision", "kind", "value", "mac_profile", "target_kind"); err != nil {
		return err
	}
	type plain RadiusCriterionYAML
	return n.Decode((*plain)(r))
}

func (f *FilterYAML) UnmarshalYAML(n *yaml.Node) error {
	type plain FilterYAML
	if err := n.Decode((*plain)(f)); err != nil {
		return err
	}
	ft, err := ParseFilterType(f.Type)
	if err == nil && IsRADIUSFilter(ft) {
		return radiusKnownKeys(n, "id", "type", "pattern", "target_hunters", "enabled", "description", "radius", "revision")
	}
	return nil
}
