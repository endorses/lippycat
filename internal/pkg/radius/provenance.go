package radius

import (
	"bytes"
	"fmt"

	"github.com/google/gopacket"
)

// ValidateProvenance checks consistency, not source authentication or current
// task admission. Inherited ownership cannot be proved by one response packet:
// callers must establish capture-source trust and recheck current generations.
func ValidateProvenance(o *Observation) error {
	if o == nil || o.Message == nil {
		return fmt.Errorf("missing RADIUS observation")
	}
	if o.Scope.Epoch == [16]byte{} || o.Scope.OriginNodeID == "" || o.Scope.SourceID == "" || o.Capture.ID.Epoch != o.Scope.Epoch || o.Capture.ID.Sequence == 0 {
		return fmt.Errorf("invalid RADIUS capture identity")
	}
	decoded, _, err := DecodePacket(o.Packet, o.Capture.LinkType, gopacket.CaptureInfo{Timestamp: o.Capture.Timestamp, CaptureLength: o.Capture.CapturedLength, Length: o.Capture.OriginalLength}, o.Scope, o.Capture.ID, o.Endpoints.Server.Port())
	if err != nil {
		return fmt.Errorf("validate RADIUS captured bytes: %w", err)
	}
	if !bytes.Equal(decoded.Message.Raw, o.Message.Raw) || decoded.Endpoints != o.Endpoints {
		return fmt.Errorf("RADIUS envelope differs from captured bytes")
	}
	switch o.Association.Status {
	case AssociationUnprocessed, AssociationMissing, AssociationAmbiguous, AssociationExpired, AssociationIncompatible, AssociationCapacitySuppressed:
		if o.Association.RequestInstanceID != (Identity{}) || o.Association.RequestObservationID != (Identity{}) || !o.Association.RequestFirstSeen.IsZero() || len(o.Inherited) > 0 {
			return fmt.Errorf("RADIUS unresolved association carries inheritance")
		}
	case AssociationRequest, AssociationUnique:
		a := o.Association
		if a.RequestInstanceID.Epoch != o.Scope.Epoch || a.RequestObservationID.Epoch != o.Scope.Epoch || a.RequestInstanceID.Sequence == 0 || a.RequestObservationID.Sequence == 0 || a.RequestFirstSeen.IsZero() {
			return fmt.Errorf("invalid RADIUS request association")
		}
		request := decoded.Message.Code == 1 || decoded.Message.Code == 4
		if (o.Association.Status == AssociationRequest) != request || (request && len(o.Inherited) > 0) {
			return fmt.Errorf("RADIUS association incompatible with message code")
		}
	default:
		return fmt.Errorf("unsupported RADIUS association status")
	}
	for _, list := range [][]AttributionReference{o.Direct, o.Inherited} {
		for _, ref := range list {
			if ref.Scope != o.Scope || ref.CriterionGroupID == "" || len(ref.Criteria) == 0 || len(ref.Criteria) > 64 || (ref.TaskID == "") != (ref.TaskGeneration == 0) {
				return fmt.Errorf("invalid RADIUS attribution group")
			}
			for _, c := range ref.Criteria {
				if c.FilterID == "" || c.FilterRevision == 0 || len(c.Value) == 0 || len(c.Value) > 253 {
					return fmt.Errorf("invalid RADIUS attribution criterion")
				}
			}
		}
	}
	for _, ref := range o.Direct {
		for _, c := range ref.Criteria {
			p := &Predicate{attributeType: c.AttributeType, vendorID: c.VendorID, vendorType: c.VendorType, value: c.Value}
			switch c.AttributeType {
			case 1:
				if c.TargetKind != "account" && c.TargetKind != "nai" {
					return fmt.Errorf("invalid RADIUS username target")
				}
			case 31:
				p.spec.Kind = PredicateMAC
				if c.TargetKind != "mac" {
					return fmt.Errorf("invalid RADIUS MAC target")
				}
			case 87:
				if c.TargetKind != "line" {
					return fmt.Errorf("invalid RADIUS line target")
				}
			case 26:
				if c.TargetKind != "line" || c.VendorID != 3561 || c.VendorType != 1 {
					return fmt.Errorf("invalid RADIUS vendor target")
				}
			default:
				return fmt.Errorf("unsupported RADIUS criterion attribute")
			}
			if c.AttributeType != 26 && (c.VendorID != 0 || c.VendorType != 0) {
				return fmt.Errorf("unexpected RADIUS vendor criterion")
			}
			if !p.matchValidated(decoded.Message) {
				return fmt.Errorf("RADIUS direct criterion absent from captured bytes")
			}
		}
	}
	return nil
}
