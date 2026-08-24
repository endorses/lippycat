package records

import (
	"fmt"

	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/endorses/lippycat/internal/pkg/logstream"
)

// SMTP maps a normalized SMTP event to the canonical smtp.log schema.
func SMTP(event events.Event) (logstream.Record, bool, error) {
	ev, ok := event.(events.SMTPEvent)
	if !ok {
		return logstream.Record{}, false, fmt.Errorf("expected SMTP event, got %T", event)
	}
	env := ev.Envelope()
	first, second := any(logstream.Unset), any(logstream.Unset)
	if len(ev.Received) > 0 {
		first = ev.Received[0]
	}
	if len(ev.Received) > 1 {
		second = ev.Received[1]
	}
	record, err := logstream.NewRecord("smtp",
		env.Timestamp, env.UID, env.Flow.SourceAddress, env.Flow.SourcePort,
		env.Flow.DestinationAddress, env.Flow.DestinationPort, ev.TransactionDepth,
		optionalString(ev.HELO), optionalString(ev.MailFrom), ev.Recipients, optionalString(ev.Date), optionalString(ev.From),
		ev.To, ev.CC, optionalString(ev.ReplyTo), optionalString(ev.MessageID), optionalString(ev.InReplyTo), optionalString(ev.Subject),
		ev.OriginatingIP, first, second, optionalString(ev.LastReply), ev.Path, optionalString(ev.UserAgent), ev.TLS,
		ev.FileIDs, ev.IsWebmail, env.CommunityID, env.NodeID,
	)
	return record, err == nil, err
}

func optionalString(value string) any {
	if value == "" {
		return logstream.Unset
	}
	return value
}
