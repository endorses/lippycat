package grpcadapter

import (
	"bytes"
	"fmt"
	"time"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/internal/pkg/radius"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func radiusIDToProto(id radius.Identity) *data.RADIUSIdentity {
	if id == (radius.Identity{}) {
		return nil
	}
	return &data.RADIUSIdentity{Epoch: append([]byte(nil), id.Epoch[:]...), Sequence: id.Sequence}
}
func radiusIDFromProto(id *data.RADIUSIdentity) (radius.Identity, error) {
	if id == nil {
		return radius.Identity{}, nil
	}
	if len(id.Epoch) != 16 || id.Sequence == 0 {
		return radius.Identity{}, fmt.Errorf("invalid RADIUS identity")
	}
	return radius.Identity{Epoch: [16]byte(id.Epoch), Sequence: id.Sequence}, nil
}
func radiusScopeToProto(s radius.CaptureScope) *data.RADIUSScope {
	return &data.RADIUSScope{OriginNodeId: s.OriginNodeID, Epoch: append([]byte(nil), s.Epoch[:]...), SourceId: s.SourceID, OperatorScope: s.OperatorScope, ProfileRevision: s.ProfileRevision}
}
func radiusScopeFromProto(s *data.RADIUSScope) (radius.CaptureScope, error) {
	if s == nil || len(s.Epoch) != 16 {
		return radius.CaptureScope{}, fmt.Errorf("invalid RADIUS scope")
	}
	return radius.CaptureScope{OriginNodeID: s.OriginNodeId, Epoch: [16]byte(s.Epoch), SourceID: s.SourceId, OperatorScope: s.OperatorScope, ProfileRevision: s.ProfileRevision}, nil
}
func radiusRefsToProto(refs []radius.AttributionReference) []*data.RADIUSAttribution {
	out := make([]*data.RADIUSAttribution, 0, len(refs))
	for _, r := range refs {
		p := &data.RADIUSAttribution{CriterionGroupId: r.CriterionGroupID, TaskId: r.TaskID, TaskGeneration: r.TaskGeneration, Scope: radiusScopeToProto(r.Scope)}
		for _, c := range r.Criteria {
			p.Criteria = append(p.Criteria, &data.RADIUSCriterion{TargetKind: c.TargetKind, FilterId: c.FilterID, FilterRevision: c.FilterRevision, AttributeType: uint32(c.AttributeType), VendorId: c.VendorID, VendorType: uint32(c.VendorType), Value: append([]byte(nil), c.Value...)})
		}
		out = append(out, p)
	}
	return out
}
func radiusRefsFromProto(refs []*data.RADIUSAttribution) ([]radius.AttributionReference, error) {
	if len(refs) > 1024 {
		return nil, fmt.Errorf("too many RADIUS attribution groups")
	}
	var out []radius.AttributionReference
	for _, r := range refs {
		if r == nil || len(r.Criteria) > 64 {
			return nil, fmt.Errorf("invalid RADIUS attribution")
		}
		s, err := radiusScopeFromProto(r.Scope)
		if err != nil {
			return nil, err
		}
		v := radius.AttributionReference{CriterionGroupID: r.CriterionGroupId, TaskID: r.TaskId, TaskGeneration: r.TaskGeneration, Scope: s}
		for _, c := range r.Criteria {
			if c == nil || c.AttributeType > 255 || c.VendorType > 255 || len(c.Value) > 253 {
				return nil, fmt.Errorf("invalid RADIUS criterion")
			}
			v.Criteria = append(v.Criteria, radius.CriterionReference{TargetKind: c.TargetKind, FilterID: c.FilterId, FilterRevision: c.FilterRevision, AttributeType: uint8(c.AttributeType), VendorID: c.VendorId, VendorType: uint8(c.VendorType), Value: append([]byte(nil), c.Value...)})
		}
		out = append(out, v)
	}
	return out, nil
}

// RADIUSToProto preserves grouped capture claims. Raw captured bytes remain in
// CapturedPacket.Data; no routine display/log consumer should dump this message.
func RADIUSToProto(o *radius.Observation) *data.RADIUSObservation {
	if o == nil || o.Message == nil {
		return nil
	}
	return &data.RADIUSObservation{Version: 1, Scope: radiusScopeToProto(o.Scope), ObservationId: radiusIDToProto(o.Capture.ID), Message: append([]byte(nil), o.Message.Raw...), AssociationStatus: string(o.Association.Status), RequestInstanceId: radiusIDToProto(o.Association.RequestInstanceID), RequestObservationId: radiusIDToProto(o.Association.RequestObservationID), RequestFirstSeenNs: unixNano(o.Association.RequestFirstSeen), Direct: radiusRefsToProto(o.Direct), Inherited: radiusRefsToProto(o.Inherited), ServicePort: uint32(o.Endpoints.Server.Port())}
}

// RADIUSFromProto rebuilds attributes and endpoints from captured bytes, then
// validates correlation claims. Success does NOT authenticate an origin or
// authorize a task. Relays retain the original scope rather than replacing it
// with the immediate peer ID; admission must independently trust that path.
func RADIUSFromProto(p *data.CapturedPacket) (*radius.Observation, error) {
	if p == nil || p.Radius == nil {
		return nil, nil
	}
	r := p.Radius
	if r.Version != 1 || r.ServicePort == 0 || r.ServicePort > 65535 || p.LinkType > 255 {
		return nil, fmt.Errorf("unsupported RADIUS transport profile")
	}
	scope, err := radiusScopeFromProto(r.Scope)
	if err != nil {
		return nil, err
	}
	id, err := radiusIDFromProto(r.ObservationId)
	if err != nil {
		return nil, err
	}
	o, _, err := radius.DecodePacket(p.Data, layers.LinkType(p.LinkType), gopacket.CaptureInfo{Timestamp: time.Unix(0, p.TimestampNs), CaptureLength: int(p.CaptureLength), Length: int(p.OriginalLength)}, scope, id, uint16(r.ServicePort))
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(o.Message.Raw, r.Message) || uint32(o.Endpoints.Server.Port()) != r.ServicePort {
		return nil, fmt.Errorf("RADIUS message differs from captured bytes")
	}
	o.Association.Status = radius.AssociationStatus(r.AssociationStatus)
	o.Association.RequestInstanceID, err = radiusIDFromProto(r.RequestInstanceId)
	if err != nil {
		return nil, err
	}
	o.Association.RequestObservationID, err = radiusIDFromProto(r.RequestObservationId)
	if err != nil {
		return nil, err
	}
	if r.RequestFirstSeenNs != 0 {
		o.Association.RequestFirstSeen = time.Unix(0, r.RequestFirstSeenNs).UTC()
	}
	o.Direct, err = radiusRefsFromProto(r.Direct)
	if err != nil {
		return nil, err
	}
	o.Inherited, err = radiusRefsFromProto(r.Inherited)
	if err != nil {
		return nil, err
	}
	if err = radius.ValidateProvenance(o); err != nil {
		return nil, err
	}
	return o, nil
}
