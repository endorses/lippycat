package events

import (
	"encoding/hex"
	"github.com/endorses/lippycat/internal/pkg/radius"
)

const KindRADIUS Kind = "radius"

// RADIUSEvent is one observed message, not a subscriber session. It deliberately
// excludes message bytes, authenticators, credential attributes and LI evidence.
type RADIUSEvent struct {
	eventBase
	Code, Identifier                              uint8
	Length                                        uint16
	ObservationID, RequestInstanceID, Association string
	OriginNodeID, SourceID, CaptureEpoch          string
	Attributes                                    []string
}

func NewRADIUSEvent(env Envelope) RADIUSEvent { return RADIUSEvent{eventBase: eventBase{env}} }
func (RADIUSEvent) Kind() Kind                { return KindRADIUS }
func (RADIUSEvent) eventMarker()              {}

// RADIUSFromObservation retains observed packet direction. Each response gets
// its own event, including identity-free responses with a shared request ID.
func RADIUSFromObservation(env Envelope, observation *radius.Observation) (RADIUSEvent, bool) {
	ev := NewRADIUSEvent(env)
	if observation == nil || observation.Message == nil {
		return ev, false
	}
	ev.Code, ev.Identifier, ev.Length = observation.Message.Code, observation.Message.Identifier, observation.Message.Length
	ev.ObservationID = radius.IdentityString(observation.Capture.ID)
	ev.RequestInstanceID = radius.IdentityString(observation.Association.RequestInstanceID)
	ev.Association = string(observation.Association.Status)
	ev.OriginNodeID, ev.SourceID = observation.Scope.OriginNodeID, observation.Scope.SourceID
	ev.CaptureEpoch = hex.EncodeToString(observation.Scope.Epoch[:])
	ev.Attributes = radius.PublicAttributes(observation.Message)
	return ev, true
}
