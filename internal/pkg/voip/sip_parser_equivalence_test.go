package voip

import (
	"reflect"
	"testing"

	sharedsip "github.com/endorses/lippycat/internal/pkg/sip"
)

func TestSharedSIPParserCompatibilityAdapters(t *testing.T) {
	sdp := "v=0\r\nm=audio 49170 RTP/AVP 0\r\n"
	type corpusEntry struct {
		message []byte
		legacy  normalizedSIPResult
	}
	corpus := []corpusEntry{
		{
			message: []byte("INVITE sip:b@example.test SIP/2.0\r\nCall-ID: invite-call\r\nFrom: <sip:a@example.test>;tag=one\r\nTo: <sip:b@example.test>\r\nCSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n"),
			legacy: normalizedSIPResult{
				CallID: "invite-call", From: "<sip:a@example.test>;tag=one", To: "<sip:b@example.test>",
				FromURI: "sip:a@example.test", ToURI: "sip:b@example.test", FromUser: "a", ToUser: "b",
				FromTag: "one", Method: "INVITE", CSeqMethod: "INVITE",
			},
		},
		{
			message: []byte("SIP/2.0 183 Session Progress\r\ni: invite-call\r\nf: <sip:a@example.test>;tag=one\r\nt: <sip:b@example.test>;tag=two\r\nCSeq: 1 INVITE\r\nl: 0\r\n\r\n"),
			legacy: normalizedSIPResult{
				CallID: "invite-call", From: "<sip:a@example.test>;tag=one", To: "<sip:b@example.test>;tag=two",
				FromURI: "sip:a@example.test", ToURI: "sip:b@example.test", FromUser: "a", ToUser: "b",
				FromTag: "one", ToTag: "two", Method: "RESPONSE", CSeqMethod: "INVITE", ResponseCode: 183,
			},
		},
		{
			message: []byte("SIP/2.0 200 OK\r\nCall-ID: invite-call\r\nFrom: <sip:a@example.test>;tag=one\r\nTo: <sip:b@example.test>;tag=two\r\nCSeq: 1 INVITE\r\nContent-Type: application/sdp\r\nContent-Length: 30\r\n\r\n" + sdp),
			legacy: normalizedSIPResult{
				CallID: "invite-call", From: "<sip:a@example.test>;tag=one", To: "<sip:b@example.test>;tag=two",
				FromURI: "sip:a@example.test", ToURI: "sip:b@example.test", FromUser: "a", ToUser: "b",
				FromTag: "one", ToTag: "two", Method: "RESPONSE", CSeqMethod: "INVITE", ResponseCode: 200,
				ContentType: "application/sdp", Body: sdp, SDP: sdp,
			},
		},
		{
			message: []byte("PUBLISH sip:a@example.test SIP/2.0\r\nCall-ID: publish-call\r\nCSeq: 2 PUBLISH\r\nContent-Length: 0\r\n\r\n"),
			legacy:  normalizedSIPResult{CallID: "publish-call", Method: "PUBLISH", CSeqMethod: "PUBLISH"},
		},
	}
	for index, entry := range corpus {
		compareSharedAndLegacySIP(t, entry.message, entry.legacy, "synthetic corpus", index)
	}
}

// normalizedSIPResult is a frozen snapshot of the fields produced by the
// pre-migration parser. Keeping the reference values independent from the
// compatibility adapters prevents this test from comparing the shared parser
// with itself.
type normalizedSIPResult struct {
	CallID, From, To, FromURI, ToURI, FromUser, ToUser string
	FromTag, ToTag, PAssertedIdentity                  string
	Method, CSeqMethod, ContentType, Body, SDP         string
	ResponseCode                                       int
}

func compareSharedAndLegacySIP(t *testing.T, message []byte, legacy normalizedSIPResult, source string, index int) {
	t.Helper()
	event, err := sharedsip.Parse(message, sharedsip.ParseOptions{})
	if err != nil {
		t.Fatalf("%s message %d: %v", source, index, err)
	}
	got := normalizedSIPResult{
		CallID:            event.CallID,
		From:              event.From,
		To:                event.To,
		FromURI:           event.FromURI,
		ToURI:             event.ToURI,
		FromUser:          event.FromUser,
		ToUser:            event.ToUser,
		FromTag:           event.FromTag,
		ToTag:             event.ToTag,
		PAssertedIdentity: event.PAssertedIdentity,
		Method:            event.Method,
		CSeqMethod:        event.CSeqMethod,
		ContentType:       event.ContentType,
		ResponseCode:      event.ResponseCode,
		Body:              string(event.Body),
		SDP:               string(event.SDP),
	}
	if !reflect.DeepEqual(got, legacy) {
		t.Fatalf("%s message %d differs from legacy result: got=%+v want=%+v", source, index, got, legacy)
	}
}

func TestNormalizeHeaderNameUsesSharedCompactHeaders(t *testing.T) {
	for compact, full := range sharedsip.CompactHeaders {
		if got := normalizeHeaderName(compact); got != full {
			t.Fatalf("normalizeHeaderName(%q) = %q, want %q", compact, got, full)
		}
	}
	if got := normalizeHeaderName("p-access-network-info"); got != "p-access-network-info" {
		t.Fatalf("full header changed to %q", got)
	}
}
