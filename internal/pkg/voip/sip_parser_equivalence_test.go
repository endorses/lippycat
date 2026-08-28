package voip

import (
	"testing"

	sharedsip "github.com/endorses/lippycat/internal/pkg/sip"
)

func TestSharedSIPParserCompatibilityAdapters(t *testing.T) {
	corpus := [][]byte{
		[]byte("INVITE sip:b@example.test SIP/2.0\r\nCall-ID: invite-call\r\nFrom: <sip:a@example.test>;tag=one\r\nTo: <sip:b@example.test>\r\nCSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n"),
		[]byte("SIP/2.0 183 Session Progress\r\ni: invite-call\r\nf: <sip:a@example.test>;tag=one\r\nt: <sip:b@example.test>;tag=two\r\nCSeq: 1 INVITE\r\nl: 0\r\n\r\n"),
		[]byte("PUBLISH sip:a@example.test SIP/2.0\r\nCall-ID: publish-call\r\nCSeq: 2 PUBLISH\r\nContent-Length: 0\r\n\r\n"),
	}
	for _, message := range corpus {
		event, err := sharedsip.Parse(message, sharedsip.ParseOptions{})
		if err != nil {
			t.Fatal(err)
		}
		headers, body := parseSipHeaders(message)
		if headers["call-id"] != event.CallID || headers["from"] != event.From || headers["to"] != event.To || detectSipMethod(string(message)) != event.Method || extractCSeqMethod(headers["cseq"]) != event.CSeqMethod || int(extractSipResponseCode(message)) != event.ResponseCode {
			t.Fatalf("compatibility adapter differs from shared event: event=%+v headers=%v body=%q", event, headers, body)
		}
	}
}
