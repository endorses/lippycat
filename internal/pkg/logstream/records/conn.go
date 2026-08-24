package records

import (
	"fmt"
	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/endorses/lippycat/internal/pkg/logstream"
)

// Conn maps a normalized connection summary to the canonical conn schema.
func Conn(event events.Event) (logstream.Record, bool, error) {
	ev, ok := event.(events.ConnEvent)
	if !ok {
		return logstream.Record{}, false, fmt.Errorf("expected conn event, got %T", event)
	}
	env := ev.Envelope()
	proto := map[uint8]string{1: "icmp", 6: "tcp", 17: "udp", 58: "icmp"}[env.Flow.Protocol]
	if proto == "" {
		proto = fmt.Sprint(env.Flow.Protocol)
	}
	value := func(s string) any {
		if s == "" {
			return logstream.Unset
		}
		return s
	}
	record, err := logstream.NewRecord("conn", env.Timestamp, env.UID, env.Flow.SourceAddress, env.Flow.SourcePort, env.Flow.DestinationAddress, env.Flow.DestinationPort, proto, value(ev.Service), ev.Duration, ev.OriginBytes, ev.ResponseBytes, value(ev.State), ev.LocalOrigin, ev.LocalResponse, ev.MissedBytes, value(ev.History), ev.OriginPackets, ev.OriginIPBytes, ev.ResponsePackets, ev.ResponseIPBytes, env.CommunityID, env.NodeID, string(env.CaptureScope), env.Partial)
	return record, true, err
}
