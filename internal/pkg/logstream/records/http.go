package records

import (
	"fmt"

	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/endorses/lippycat/internal/pkg/logstream"
)

// HTTP maps normalized HTTP request/response metadata to http.log.
func HTTP(event events.Event) (logstream.Record, bool, error) {
	ev, ok := event.(events.HTTPEvent)
	if !ok {
		return logstream.Record{}, false, fmt.Errorf("expected HTTP event, got %T", event)
	}
	env := ev.Envelope()
	record, err := logstream.NewRecord("http", env.Timestamp, env.UID, env.Flow.SourceAddress, env.Flow.SourcePort, env.Flow.DestinationAddress, env.Flow.DestinationPort,
		ev.TransactionDepth, ev.Method, ev.Host, ev.URI, ev.Referrer, ev.Version, ev.UserAgent, ev.Origin, ev.RequestBodyLength, ev.ResponseBodyLength,
		ev.StatusCode, ev.StatusMessage, ev.InformationalCode, ev.InformationalMessage, ev.Tags, ev.Username, "", ev.Proxies,
		ev.RequestFileIDs, ev.RequestFilenames, ev.RequestMIMETypes, ev.ResponseFileIDs, ev.ResponseFilenames, ev.ResponseMIMETypes, env.CommunityID, env.NodeID)
	return record, true, err
}
