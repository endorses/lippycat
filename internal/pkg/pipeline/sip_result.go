package pipeline

import (
	sharedsip "github.com/endorses/lippycat/internal/pkg/sip"
	"github.com/endorses/lippycat/internal/pkg/sms"
)

// SIPResultFromEvent adapts the pure parser event to the pipeline domain result.
func SIPResultFromEvent(event sharedsip.Event, env *PacketEnvelope) SIPResult {
	return SIPResultFromEventWithSMS(event, env, nil)
}

// SIPResultFromEventWithSMS reuses supplied SMS interpretation without decoding
// its body again. The returned result owns the supplied message's mutable data.
// Nil metadata falls back to decoding a complete SMS MESSAGE body.
func SIPResultFromEventWithSMS(event sharedsip.Event, env *PacketEnvelope, message *sms.Message) SIPResult {
	result := SIPResult{
		Timestamp: event.Timestamp, CallID: event.CallID, Method: event.Method,
		CSeqMethod: event.CSeqMethod, CSeqNumber: event.CSeqNumber, ViaBranch: event.ViaBranch, ResponseCode: event.ResponseCode,
		From: event.From, To: event.To, FromUser: event.FromUser, ToUser: event.ToUser,
		FromURI: event.FromURI, ToURI: event.ToURI, FromTag: event.FromTag, ToTag: event.ToTag,
		PAssertedIdentity: event.PAssertedIdentity, ContentType: event.ContentType,
		Body: append([]byte(nil), event.Body...), Headers: cloneSIPHeaders(event.Headers),
		DuplicateReliableHeaders: event.DuplicateReliableHeaders,
		ReliableHeaderEvidence:   event.ReliableHeaderEvidence,
		SourceIP:                 event.SourceIP, DestinationIP: event.DestinationIP,
		SourcePort: event.SourcePort, DestinationPort: event.DestinationPort,
		SDP: append([]byte(nil), event.SDP...), Packet: env,
	}
	result.SMS = sms.Clone(message)
	if result.SMS == nil && event.Method == "MESSAGE" && sms.IsSMS(event.ContentType) {
		decoded, err := sms.Decode(event.Body)
		// Decode returns an owned partial result on failure. Its bounded status
		// is useful metadata, and malformed SMS does not reject eligible SIP.
		if err != nil && decoded == nil {
			decoded = &sms.Message{Status: sms.StatusMalformed}
		}
		result.SMS = decoded
	}
	return result
}

func cloneSIPHeaders(headers map[string]string) map[string]string {
	if headers == nil {
		return nil
	}
	cloned := make(map[string]string, len(headers))
	for key, value := range headers {
		cloned[key] = value
	}
	return cloned
}
