package types

import (
	"fmt"

	"github.com/endorses/lippycat/internal/pkg/radius"
	"github.com/google/gopacket/layers"
)

// RADIUSMetadata contains only the public observation projection. Raw messages,
// authenticators and attribution criteria never enter routine presentation.
type RADIUSMetadata struct {
	Code          uint8    `json:"code"`
	CodeName      string   `json:"code_name"`
	Identifier    uint8    `json:"identifier"`
	MessageLength uint16   `json:"message_length"`
	Association   string   `json:"association"`
	ObservationID string   `json:"observation_id,omitempty"`
	RequestID     string   `json:"request_id,omitempty"`
	Attributes    []string `json:"attributes,omitempty"`
}

func RADIUSMetadataFromObservation(o *radius.Observation) *RADIUSMetadata {
	if o == nil || o.Message == nil {
		return nil
	}
	m := &RADIUSMetadata{Code: o.Message.Code, CodeName: layers.RADIUSCode(o.Message.Code).String(), Identifier: o.Message.Identifier, MessageLength: o.Message.Length, Association: string(o.Association.Status), Attributes: radius.PublicAttributes(o.Message)}
	if o.Capture.ID.Sequence != 0 {
		m.ObservationID = fmt.Sprintf("%x:%d", o.Capture.ID.Epoch, o.Capture.ID.Sequence)
	}
	if o.Association.RequestInstanceID.Sequence != 0 {
		m.RequestID = fmt.Sprintf("%x:%d", o.Association.RequestInstanceID.Epoch, o.Association.RequestInstanceID.Sequence)
	}
	return m
}

func (m *RADIUSMetadata) Summary() string {
	if m == nil {
		return ""
	}
	return fmt.Sprintf("%s id=%d length=%d association=%s", m.CodeName, m.Identifier, m.MessageLength, m.Association)
}
