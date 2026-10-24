package pipeline

import (
	"testing"

	sharedsip "github.com/endorses/lippycat/internal/pkg/sip"
	"github.com/endorses/lippycat/internal/pkg/sms"
	"github.com/stretchr/testify/require"
)

func TestSIPResultDecodesOnlySMSMessageBodies(t *testing.T) {
	// MO RP-DATA with a GSM7 SMS-SUBMIT containing successful empty user text.
	body := []byte{0, 1, 0, 0, 8, 1, 0, 2, 0x91, 0x21, 0, 0, 0}
	for _, tc := range []struct {
		name, method, contentType string
		body                      []byte
		status                    sms.DecodeStatus
	}{
		{"empty text", "MESSAGE", "application/vnd.3gpp.sms", body, sms.StatusDecoded},
		{"mime parameters", "MESSAGE", "Application/Vnd.3gpp.Sms; charset=binary", body, sms.StatusDecoded},
		{"control", "MESSAGE", "application/vnd.3gpp.sms", []byte{2, 1}, sms.StatusControl},
		{"truncated", "MESSAGE", "application/vnd.3gpp.sms", []byte{0}, sms.StatusIncomplete},
		{"plain SIP", "MESSAGE", "text/plain", []byte("hello"), ""},
		{"other method", "INVITE", "application/vnd.3gpp.sms", body, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			event := sharedsip.Event{Method: tc.method, ContentType: tc.contentType, Body: append([]byte(nil), tc.body...)}
			result := SIPResultFromEvent(event, nil)
			if tc.status == "" {
				require.Nil(t, result.SMS)
			} else {
				require.NotNil(t, result.SMS)
				require.Equal(t, tc.status, result.SMS.Status)
			}
			require.Equal(t, tc.body, result.Body)
			event.Body[0] = 99
			require.Equal(t, tc.body, result.Body, "binary SIP body remains independently owned")
		})
	}
}

func TestSIPResultReusesOwnedSuppliedSMS(t *testing.T) {
	supplied := &sms.Message{Status: sms.StatusDecoded, Text: "upstream text", Header: []byte{1}, Concat: &sms.Concatenation{Reference: 2, ReferenceBits: 8, Total: 2, Part: 1}}
	event := sharedsip.Event{Method: "MESSAGE", ContentType: "application/vnd.3gpp.sms", Body: []byte{0}}
	result := SIPResultFromEventWithSMS(event, nil, supplied)
	require.Equal(t, sms.StatusDecoded, result.SMS.Status, "supplied metadata supersedes the truncated raw body")
	supplied.Header[0] = 2
	supplied.Concat.Part = 2
	require.EqualValues(t, 1, result.SMS.Header[0])
	require.EqualValues(t, 1, result.SMS.Concat.Part)
}
