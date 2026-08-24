package records

import (
	"fmt"

	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/endorses/lippycat/internal/pkg/logstream"
)

// SSL maps normalized TLS handshake metadata to ssl.log.
func SSL(event events.Event) (logstream.Record, bool, error) {
	ev, ok := event.(events.TLSEvent)
	if !ok {
		return logstream.Record{}, false, fmt.Errorf("expected TLS event, got %T", event)
	}
	env := ev.Envelope()
	record, err := logstream.NewRecord("ssl", env.Timestamp, env.UID, env.Flow.SourceAddress, env.Flow.SourcePort, env.Flow.DestinationAddress, env.Flow.DestinationPort,
		ev.Version, ev.Cipher, ev.Curve, ev.ServerName, ev.Resumed, ev.LastAlert, ev.NextProtocol, ev.Established,
		ev.CertificateFileIDs, ev.ClientCertificateFileIDs, ev.Subject, ev.Issuer, ev.ClientSubject, ev.ClientIssuer, ev.ValidationStatus,
		ev.JA3, ev.JA3S, ev.JA4, env.CommunityID, env.NodeID)
	return record, true, err
}
