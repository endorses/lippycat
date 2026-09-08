package radius

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"strings"
	"unicode/utf8"
)

const (
	PredicateUserName         = "username"
	PredicateMAC              = "mac"
	PredicateAttribute        = "attribute"
	MACProfileUppercaseHyphen = "calling-station-id-uppercase-hyphen-v1"
)

// PredicateSpec is the portable provisioning form. Value is literal UTF-8 for
// username, the selected profile's spelling for MAC, or one complete hex AVP.
// TargetKind retains administrative identity independently of wire matching.
type PredicateSpec struct {
	Kind           string `json:"kind"`
	Value          string `json:"value"`
	MACProfile     string `json:"mac_profile,omitempty"`
	TargetKind     string `json:"target_kind,omitempty"`
	FilterID       string `json:"filter_id,omitempty"`
	FilterRevision uint64 `json:"filter_revision,omitempty"`
}

// Predicate is immutable and safe for concurrent matching.
type Predicate struct {
	spec          PredicateSpec
	attributeType uint8
	vendorID      uint32
	vendorType    uint8
	value         []byte
}

// CompilePredicate validates targets without normalizing identity bytes.
func CompilePredicate(spec PredicateSpec) (*Predicate, error) {
	p := &Predicate{spec: spec}
	switch spec.Kind {
	case PredicateUserName:
		if !utf8.ValidString(spec.Value) || len(spec.Value) == 0 || len(spec.Value) > 253 {
			return nil, fmt.Errorf("RADIUS User-Name requires 1–253 valid UTF-8 bytes")
		}
		p.attributeType = 1
		p.value = []byte(spec.Value)
		if spec.TargetKind == "" {
			p.spec.TargetKind = "account"
		}
		if p.spec.TargetKind != "account" && p.spec.TargetKind != "nai" {
			return nil, fmt.Errorf("unsupported User-Name target kind %q", spec.TargetKind)
		}
	case PredicateMAC:
		if spec.MACProfile != MACProfileUppercaseHyphen {
			return nil, fmt.Errorf("RADIUS MAC requires explicit supported profile")
		}
		value, ok := parseProfileMAC([]byte(spec.Value))
		if !ok {
			return nil, fmt.Errorf("invalid RADIUS subscriber MAC spelling")
		}
		p.attributeType = 31
		p.value = value
		if spec.TargetKind == "" {
			p.spec.TargetKind = "mac"
		}
		if p.spec.TargetKind != "mac" {
			return nil, fmt.Errorf("unsupported MAC target kind %q", spec.TargetKind)
		}
	case PredicateAttribute:
		raw, err := hex.DecodeString(strings.Trim(spec.Value, " \t\r\n"))
		if err != nil {
			return nil, fmt.Errorf("decode RADIUS AVP hex: %w", err)
		}
		if len(raw) < 3 || len(raw) > 255 || int(raw[1]) != len(raw) {
			return nil, fmt.Errorf("RADIUS target must be exactly one nonempty complete AVP")
		}
		a := Attribute{Type: raw[0], Raw: raw, Value: raw[2:]}
		if err := validateAttribute(&a); err != nil {
			return nil, fmt.Errorf("invalid RADIUS target AVP: %w", err)
		}
		p.attributeType = a.Type
		p.value = append([]byte(nil), a.Value...)
		switch a.Type {
		case 1, 87:
		case 26:
			if a.VendorID != DSLForumVendorID || len(a.VendorAttributes) != 1 || a.VendorAttributes[0].Type != 1 {
				return nil, fmt.Errorf("RADIUS target VSA requires vendor 3561 and exactly one type-1 sub-attribute")
			}
			p.vendorID = a.VendorID
			p.vendorType = 1
			p.value = append([]byte(nil), a.VendorAttributes[0].Value...)
		default:
			return nil, fmt.Errorf("unsupported RADIUS target attribute %d", a.Type)
		}
		if spec.TargetKind == "" {
			if a.Type == 1 {
				p.spec.TargetKind = "account"
			} else {
				p.spec.TargetKind = "line"
			}
		}
		if (a.Type == 1 && p.spec.TargetKind != "account" && p.spec.TargetKind != "nai") || (a.Type != 1 && p.spec.TargetKind != "line") {
			return nil, fmt.Errorf("unsupported RADIUS AVP target kind %q", spec.TargetKind)
		}
		p.spec.Value = strings.ToUpper(hex.EncodeToString(raw))
	default:
		return nil, fmt.Errorf("unsupported RADIUS predicate kind %q", spec.Kind)
	}
	if spec.Kind != PredicateMAC && spec.MACProfile != "" {
		return nil, fmt.Errorf("MAC profile on non-MAC predicate")
	}
	return p, nil
}

// Spec returns the canonical, serializable provisioning representation.
func (p *Predicate) Spec() PredicateSpec { return p.spec }

// Match validates the complete raw message before inspecting any attributes.
// Decoded fields supplied by an adapter are never trusted over original bytes.
func (p *Predicate) Match(message *Message) (bool, error) {
	if p == nil || p.spec.Kind == "" {
		return false, fmt.Errorf("uninitialized RADIUS predicate")
	}
	if message == nil {
		return false, fmt.Errorf("missing RADIUS message")
	}
	decoded, err := Decode(message.Raw)
	if err != nil {
		return false, err
	}
	if len(decoded.Raw) != len(message.Raw) {
		return false, fmt.Errorf("RADIUS message contains undeclared trailing bytes")
	}
	return p.matchValidated(decoded), nil
}

func (p *Predicate) matchValidated(message *Message) bool {
	for _, a := range message.Attributes {
		if a.Type != p.attributeType {
			continue
		}
		if p.spec.Kind == PredicateMAC {
			value, ok := parseProfileMAC(a.Value)
			if ok && bytes.Equal(value, p.value) {
				return true
			}
			continue
		}
		if p.vendorID != 0 {
			if a.VendorID == p.vendorID {
				for _, v := range a.VendorAttributes {
					if v.Type == p.vendorType && bytes.Equal(v.Value, p.value) {
						return true
					}
				}
			}
			continue
		}
		if bytes.Equal(a.Value, p.value) {
			return true
		}
	}
	return false
}

func parseProfileMAC(value []byte) ([]byte, bool) {
	if len(value) != 17 {
		return nil, false
	}
	out := make([]byte, 6)
	for i := range out {
		offset := i * 3
		if i > 0 && value[offset-1] != '-' {
			return nil, false
		}
		for j := 0; j < 2; j++ {
			c := value[offset+j]
			if c >= '0' && c <= '9' {
				out[i] = out[i]*16 + c - '0'
			} else if c >= 'A' && c <= 'F' {
				out[i] = out[i]*16 + c - 'A' + 10
			} else {
				return nil, false
			}
		}
	}
	return out, true
}

// ScopeBinding identifies the configured dedicated capture domain. Empty origin
// or source selects all admitted sources in that domain; it does not establish
// source trust. Authentication/admission must establish CaptureScope separately.
type ScopeBinding struct {
	OperatorScope   string `json:"operator_scope"`
	ProfileRevision string `json:"profile_revision"`
	OriginNodeID    string `json:"origin_node_id,omitempty"`
	SourceID        string `json:"source_id,omitempty"`
}

type GroupSpec struct {
	ID             string          `json:"id"`
	TaskID         string          `json:"task_id,omitempty"`
	TaskGeneration uint64          `json:"task_generation,omitempty"`
	Scope          ScopeBinding    `json:"scope"`
	Criteria       []PredicateSpec `json:"criteria"`
}

// Group preserves a single owner's conjunction. Ordinary groups leave TaskID
// empty. A matching group is evidence, never an LI authorization decision.
type Group struct {
	spec       GroupSpec
	predicates []*Predicate
}

func CompileGroup(spec GroupSpec) (*Group, error) {
	if spec.ID == "" || len(spec.Criteria) == 0 || len(spec.Criteria) > 64 {
		return nil, fmt.Errorf("RADIUS group requires ID and 1–64 criteria")
	}
	if spec.Scope.OperatorScope == "" || spec.Scope.ProfileRevision == "" {
		return nil, fmt.Errorf("RADIUS group requires dedicated operator scope and profile revision")
	}
	if (spec.TaskID == "") != (spec.TaskGeneration == 0) {
		return nil, fmt.Errorf("RADIUS task ID and positive generation must be supplied together")
	}
	g := &Group{spec: spec}
	g.spec.Criteria = make([]PredicateSpec, len(spec.Criteria))
	for i, s := range spec.Criteria {
		if s.FilterID == "" || s.FilterRevision == 0 {
			return nil, fmt.Errorf("RADIUS criterion requires filter ID and positive revision")
		}
		p, err := CompilePredicate(s)
		if err != nil {
			return nil, fmt.Errorf("RADIUS criterion %d: %w", i, err)
		}
		g.predicates = append(g.predicates, p)
		g.spec.Criteria[i] = p.Spec()
	}
	return g, nil
}

func (g *Group) Spec() GroupSpec {
	result := g.spec
	result.Criteria = append([]PredicateSpec(nil), result.Criteria...)
	return result
}

func (g *Group) Match(observation *Observation) (AttributionReference, bool, error) {
	if g == nil || len(g.predicates) == 0 {
		return AttributionReference{}, false, fmt.Errorf("uninitialized RADIUS criterion group")
	}
	if observation == nil || observation.Message == nil {
		return AttributionReference{}, false, fmt.Errorf("missing RADIUS observation message")
	}
	decoded, err := Decode(observation.Message.Raw)
	if err != nil {
		return AttributionReference{}, false, err
	}
	if len(decoded.Raw) != len(observation.Message.Raw) {
		return AttributionReference{}, false, fmt.Errorf("RADIUS message contains undeclared trailing bytes")
	}
	scope := observation.Scope
	binding := g.spec.Scope
	if scope.OperatorScope != binding.OperatorScope || scope.ProfileRevision != binding.ProfileRevision || scope.OriginNodeID == "" || scope.SourceID == "" || scope.Epoch == [16]byte{} || observation.Capture.ID.Epoch != scope.Epoch || observation.Capture.ID.Sequence == 0 || (binding.OriginNodeID != "" && binding.OriginNodeID != scope.OriginNodeID) || (binding.SourceID != "" && binding.SourceID != scope.SourceID) {
		return AttributionReference{}, false, nil
	}
	for _, p := range g.predicates {
		if !p.matchValidated(decoded) {
			return AttributionReference{}, false, nil
		}
	}
	result := AttributionReference{CriterionGroupID: g.spec.ID, TaskID: g.spec.TaskID, TaskGeneration: g.spec.TaskGeneration, Scope: scope}
	for _, p := range g.predicates {
		result.Criteria = append(result.Criteria, CriterionReference{TargetKind: p.spec.TargetKind, FilterID: p.spec.FilterID, FilterRevision: p.spec.FilterRevision, AttributeType: p.attributeType, VendorID: p.vendorID, VendorType: p.vendorType, Value: append([]byte(nil), p.value...)})
	}
	return result, true, nil
}

// Reference matches this ordinary filter and returns its complete evidence
// group. It requires an explicit filter generation and complete capture
// provenance. Binding to the supplied observation does not authenticate it;
// the caller must establish source trust. It never creates task authorization.
func (p *Predicate) Reference(observation *Observation) (AttributionReference, bool, error) {
	if p == nil || p.spec.Kind == "" || observation == nil {
		return AttributionReference{}, false, fmt.Errorf("missing RADIUS predicate or observation")
	}
	scope := observation.Scope
	group, err := CompileGroup(GroupSpec{ID: p.spec.FilterID, Scope: ScopeBinding{OperatorScope: scope.OperatorScope, ProfileRevision: scope.ProfileRevision, OriginNodeID: scope.OriginNodeID, SourceID: scope.SourceID}, Criteria: []PredicateSpec{p.spec}})
	if err != nil {
		return AttributionReference{}, false, err
	}
	return group.Match(observation)
}
