package records

import (
	"fmt"
	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/endorses/lippycat/internal/pkg/logstream"
)

// RADIUS maps an observation to the version-1 canonical radius stream.
func RADIUS(event events.Event) (logstream.Record, bool, error) {
	ev, ok := event.(events.RADIUSEvent)
	if !ok {
		return logstream.Record{}, false, fmt.Errorf("expected RADIUS event, got %T", event)
	}
	env := ev.Envelope()
	var requestID any = ev.RequestInstanceID
	if ev.RequestInstanceID == "" {
		requestID = logstream.Unset
	}
	record, err := logstream.NewRecord("radius", env.Timestamp, env.UID, env.Flow.SourceAddress, env.Flow.SourcePort,
		env.Flow.DestinationAddress, env.Flow.DestinationPort, protocolName(env.Flow.Protocol), ev.Code, ev.Identifier, ev.Length,
		ev.ObservationID, requestID, ev.Association, ev.Attributes, ev.OriginNodeID, ev.SourceID, ev.CaptureEpoch, env.CommunityID, env.NodeID)
	return record, err == nil, err
}
