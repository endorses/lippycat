package li

import "github.com/google/uuid"

// DeliveryProvenance is the immutable closed union carried with encoded product.
// Journal codecs enforce the exact fields for each Kind/SourceKind; a zero value
// is permitted only by legacy memory-only APIs and compatible legacy X2 reads.
type DeliveryProvenance struct {
	Kind                string    `json:"kind"`
	SourceKind          string    `json:"source_kind,omitempty"`
	CallIncarnation     uuid.UUID `json:"call_incarnation,omitempty"`
	CallGeneration      uint64    `json:"call_generation,omitempty"`
	CallID              string    `json:"call_id,omitempty"`
	OriginNodeID        string    `json:"origin_node_id,omitempty"`
	SourceID            string    `json:"source_id,omitempty"`
	CaptureEpoch        uuid.UUID `json:"capture_epoch,omitempty"`
	ObservationSequence uint64    `json:"observation_sequence,omitempty"`
	Transport           uint8     `json:"transport,omitempty"`
	SourceAddress       string    `json:"source_address,omitempty"`
	DestinationAddress  string    `json:"destination_address,omitempty"`
	SourcePort          uint16    `json:"source_port,omitempty"`
	DestinationPort     uint16    `json:"destination_port,omitempty"`
	SSRC                uint32    `json:"ssrc,omitempty"`
	OperatorScope       string    `json:"operator_scope,omitempty"`
	ProfileRevision     string    `json:"profile_revision,omitempty"`
	NFID                string    `json:"nfid,omitempty"`
	IPID                string    `json:"ipid,omitempty"`
	CorrelationID       uint64    `json:"correlation_id,omitempty"`
}

// DeliveryCallIdentity names one task's exact captured call. Destination copies
// share this closure identity; endpoint identities remain bound on each product.
type DeliveryCallIdentity struct {
	StateIncarnation uuid.UUID
	CallIncarnation  uuid.UUID
	XID              uuid.UUID
	TaskGeneration   uint64
	CallGeneration   uint64
	CallID           string
}
