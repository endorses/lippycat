package pipeline

import sharedsip "github.com/endorses/lippycat/internal/pkg/sip"

// SIPResultFromEvent adapts the pure parser event to the pipeline domain result.
func SIPResultFromEvent(event sharedsip.Event, env *PacketEnvelope) SIPResult {
	return SIPResult{
		Timestamp: event.Timestamp, CallID: event.CallID, Method: event.Method,
		CSeqMethod: event.CSeqMethod, ResponseCode: event.ResponseCode,
		From: event.From, To: event.To, FromUser: event.FromUser, ToUser: event.ToUser,
		FromURI: event.FromURI, ToURI: event.ToURI, FromTag: event.FromTag, ToTag: event.ToTag,
		PAssertedIdentity: event.PAssertedIdentity, ContentType: event.ContentType,
		SourceIP: event.SourceIP, DestinationIP: event.DestinationIP,
		SourcePort: event.SourcePort, DestinationPort: event.DestinationPort,
		SDP: append([]byte(nil), event.SDP...), Packet: env,
	}
}
